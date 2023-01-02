# Reflected XSS protected by CSP, with CSP bypass

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-csp-bypass), you'll learn: Reflected XSS protected by CSP, with CSP bypass! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

This lab uses [CSP](https://portswigger.net/web-security/cross-site-scripting/content-security-policy) and contains a [reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected) vulnerability.

To solve the lab, perform a [cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) attack that bypasses the CSP and calls the `alert` function.

Please note that the intended solution to this lab is only possible in Chrome.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-30/images/Pasted%20image%2020230102020418.png)

In here, we can see there is a search box.

Let's search something:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-30/images/Pasted%20image%2020230102020449.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-30/images/Pasted%20image%2020230102020504.png)

As you can see, our input is reflected to the web page.

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-30/images/Pasted%20image%2020230102020545.png)

**We can see that the CSP (Content Security Policy) is enabled:**
```
Content-Security-Policy: default-src 'self'; object-src 'none';script-src 'self'; style-src 'self'; report-uri /csp-report?token=
```

Notice that **the `script-src` is set to `self`**, which means **only allow JavaScript to be loaded from the same origin as the page itself**.

However, we also can see there is a `report-uri` directive, which **reflects input into the actual policy**.

**If the site reflects a parameter that we can control, we can inject a semicolon to add our own CSP directives.**

Normally, it's not possible to overwrite an existing `script-src` directive. However, Chrome introduced **the `script-src-elem` directive, which allows you to control `script` elements, but not events.** Crucially, this new directive allows you to overwrite existing `script-src` directives.

Armed with above information, **we can try to bypass the CSP by injecting new CSP policy.**

**Payload:**
```
/?token=;script-src-elem 'unsafe-inline'&search=<script>alert(document.domain)</script>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-30/images/Pasted%20image%2020230102022207.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-30/images/Pasted%20image%2020230102022231.png)

> Note: If you don't see the completed banner, set the `script-src-elem` to `none`.

Nice!

# What we've learned:

1. Reflected XSS protected by CSP, with CSP bypass