# DOM XSS in `innerHTML` sink using source `location.search`

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-innerhtml-sink), you'll learn: DOM XSS in `innerHTML` sink using source `location.search`! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a [DOM-based cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/dom-based) vulnerability in the search blog functionality. It uses an `innerHTML` assignment, which changes the HTML contents of a `div` element, using data from `location.search`.

To solve this lab, perform a [cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) attack that calls the `alert` function.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-4/images/Pasted%20image%2020221229054628.png)

In the home page, we can see there is a search box.

Let's search something:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-4/images/Pasted%20image%2020221229054701.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-4/images/Pasted%20image%2020221229054719.png)

As you can see, our input is reflected to the web page.

**View source page:**
```html
<section class=blog-header>
    <h1>
        <span>1 search results for '</span>
        <span id="searchMessage">test</span>
        <span>'</span>
    </h1>
    <script>
        function doSearchQuery(query) {
            document.getElementById('searchMessage').innerHTML = query;
        }
        var query = (new URLSearchParams(window.location.search)).get('search');
        if(query) {
            doSearchQuery(query);
        }
    </script>
    <hr>
</section>
```

**In here, the JavaScript will do:**

- `query` = URL's GET parameter `search` value
- If `query` is set, then call function `doSearchQuery(query)`
- Function `doSearchQuery(query)` will get the HTML content of element `searchMessage`, which is the `<span>` tag

To inject `alert()` JavaScript function, we first need to know that **`innerHTML` sink(Dangerous JavaScript function) doesn't accept `script` elements** on any modern browser.

**In order do trigger an `alert()`, we need to use event handler. Such as `onerror`:**
```html
<img src=errorpls onerror=alert(document.domain)>
```

This `<img>` tag's image source is from `errorpls`, which doesn't exist on the web server, thus causing error. Then, the `onerror` event handler will be triggered.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-4/images/Pasted%20image%2020221229055708.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-4/images/Pasted%20image%2020221229055717.png)

We successfully triggered an `alert()`!

# What we've learned:

1. DOM XSS in `innerHTML` sink using source `location.search`