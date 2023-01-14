# DOM-based open redirection

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/dom-based/open-redirection/lab-dom-open-redirection), you'll learn: DOM-based open redirection! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a DOM-based open-redirection vulnerability. To solve this lab, exploit this vulnerability and redirect the victim to the exploit server.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-4/images/Pasted%20image%2020230114180854.png)

In the home page, we can view other posts:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-4/images/Pasted%20image%2020230114180959.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-4/images/Pasted%20image%2020230114181011.png)

**View source page:**
```html
<div class="is-linkback">
    <a href='#' onclick='returnUrl = /url=(https?:\/\/.+)/.exec(location); if(returnUrl)location.href = returnUrl[1];else location.href = "/"'>Back to Blog</a>
</div>
```

**As you can see, the "Back to Blog" link has an interesting `onclick` event.**

**Beautified:**
```js
returnUrl = /url=(https?:\/\/.+)/.exec(location);

if (returnUrl) {
	location.href = returnUrl[1];
} else {
	location.href = "/"
}
```

Let's break it down:

It checks the `location` object has `url=http://anything.com` or `url=https://anything.com`. If it has, then set the `location.href` attribute's property to `http://anything.com` or `https://anything.com`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-4/images/Pasted%20image%2020230114182019.png)

Armed with above information, it's vulnerable to DOM-based open redirect.

**To exploit that, we can append the payload as the GET parameter:**
```
/post?postId=7&url=https://exploit-0abd007e03655508c0bc0e3d01ea0028.exploit-server.net/
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-4/images/Pasted%20image%2020230114182313.png)

When we click the "Back to Blog", it'll redirect us to the exploit server:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-4/images/Pasted%20image%2020230114182341.png)s

# What we've learned:

1. DOM-based open redirection