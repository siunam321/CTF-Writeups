# Stored XSS into `onclick` event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-onclick-event-angle-brackets-double-quotes-html-encoded-single-quotes-backslash-escaped), you'll learn: Stored XSS into `onclick` event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a [stored cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/stored) vulnerability in the comment functionality.

To solve this lab, submit a comment that calls the `alert` function when the comment author name is clicked.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-23/images/Pasted%20image%2020230101045247.png)

In here, we can view one of those posts:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-23/images/Pasted%20image%2020230101045320.png)

And we can leave some comments.

Let's try to inject an XSS payload in the `Website` field:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-23/images/Pasted%20image%2020230101050248.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-23/images/Pasted%20image%2020230101050325.png)

As you can see, **our input is inside the `<a>` tag's `onclick` event.**

```js
var tracker={track(){}};tracker.track('<our_input>');
```

**Let's try to break out of that JavaScript code:**
```js
';+alert(document.domain)+';
```

**So the result will be:**
```js
var tracker={track(){}};tracker.track('';+alert(document.domain)+';');
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-23/images/Pasted%20image%2020230101050834.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-23/images/Pasted%20image%2020230101050922.png)

However, **our `'` is HTML encoded.**

**Let's try to escape that via `\`:**
```js
\';+alert(document.domain)+\';
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-23/images/Pasted%20image%2020230101051006.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-23/images/Pasted%20image%2020230101051040.png)

Hmm... **It escaped our `\` too.**

Now, when the browser has parsed out the HTML tags and attributes within a response, **it will perform HTML-decoding of tag attribute values before they are processed any further**. If the server-side application blocks or sanitizes certain characters that are needed for a successful XSS exploit, we can often **bypass the input validation by HTML-encoding those characters**.

**Hence, our final payload will be:**
```js
&apos;+alert(document.domain)+&apos;
```

> Note: The `&apos;` sequence is an HTML entity representing an apostrophe or single quote.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-23/images/Pasted%20image%2020230101051410.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-23/images/Pasted%20image%2020230101051429.png)

Nice!

# What we've learned:

1. Stored XSS into `onclick` event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped