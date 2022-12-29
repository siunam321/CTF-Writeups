# DOM XSS in jQuery anchor `href` attribute sink using `location.search` source

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-href-attribute-sink), you'll learn: DOM XSS in jQuery anchor `href` attribute sink using `location.search` source! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a [DOM-based cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/dom-based) vulnerability in the submit feedback page. It uses the jQuery library's `$` selector function to find an anchor element, and changes its `href` attribute using data from `location.search`.

To solve this lab, make the "back" link alert `document.cookie`.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-5/images/Pasted%20image%2020221229060409.png)

**Feedback page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-5/images/Pasted%20image%2020221229060440.png)

**View source page:**
```html
<div class="container is-page">
    <header class="navigation-header">
        <section class="top-links">
            <a href=/>Home</a><p>|</p>
            <a href="/feedback?returnPath=/feedback">Submit feedback</a><p>|</p>
        </section>
    </header>
    <header class="notification-header">
    </header>
    <h1>Submit feedback</h1>
    <form id="feedbackForm" action="/feedback/submit" method="POST" enctype="application/x-www-form-urlencoded">
        <input required type="hidden" name="csrf" value="pVfg6zkCS3aO61ExI2iwx3pX3vCjzelW">
        <label>Name:</label>
        <input required type="text" name="name">
        <label>Email:</label>
        <input required type="email" name="email">
        <label>Subject:</label>
        <input required type="text" name="subject">
        <label>Message:</label>
        <textarea required rows="12" cols="300" name="message"></textarea>
        <button class="button" type="submit">
            Submit feedback
        </button>
        <span id="feedbackResult"></span>
        <script src="/resources/js/jquery_1-8-2.js"></script>
        <div class="is-linkback">
            <a id="backLink">Back</a>
        </div>
        <script>
            $(function() {
                $('#backLink').attr("href", (new URLSearchParams(window.location.search)).get('returnPath'));
            });
        </script>
    </form>
    <script src="/resources/js/submitFeedback.js"></script>
    <br>
</div>
```

In here, we see **the form uses the jQuery library's `$` selector function to find an anchor element, and changes its `href` attribute using data from `location.search`, which is the GET parameter `returnPath`.**

Now, in jQuery, **the `attr()` function can change the attributes of DOM elements.**

If data is read from a user-controlled source like the URL, then passed to the `attr()` function, then it may be possible to manipulate the value sent to cause XSS.

**To injection malicious JavaScript, we can change our `returnPath` GET parameter:**
```js
javascript:alert(document.cookie)
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-5/images/Pasted%20image%2020221229061109.png)

**Now, when we click the `Back` link:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-5/images/Pasted%20image%2020221229061123.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-5/images/Pasted%20image%2020221229061130.png)

It'll pop up an alert box.

# What we've learned:

1. DOM XSS in jQuery anchor `href` attribute sink using `location.search` source