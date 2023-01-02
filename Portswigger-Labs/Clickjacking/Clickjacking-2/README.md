# Clickjacking with form input data prefilled from a URL parameter

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/clickjacking/lab-prefilled-form-input), you'll learn: Clickjacking with form input data prefilled from a URL parameter! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab extends the basic [clickjacking example](https://portswigger.net/web-security/clickjacking) in [Lab: Basic clickjacking with CSRF token protection](https://portswigger.net/web-security/clickjacking/lab-basic-csrf-protected). The goal of the lab is to change the email address of the user by prepopulating a form using a URL parameter and enticing the user to inadvertently click on an "Update email" button.

To solve the lab, craft some HTML that frames the account page and fools the user into updating their email address by clicking on a "Click me" decoy. The lab is solved when the email address is changed.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-2/images/Pasted%20image%2020230102050459.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-2/images/Pasted%20image%2020230102050507.png)

In the previous lab, we successfully deleted victim's account when he/she clicked our "Click me" decoy.

This time, we need to update victim's email address.

First, we can **prepopulating our evil email address via providing a GET parameter**:

```
/my-account?email=evil@attacker.com
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-2/images/Pasted%20image%2020230102050942.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-2/images/Pasted%20image%2020230102051011.png)

Then, we can craft a fake website that **tricks people to click on the "Update email" button**.

**However, instead of crafting it manually, we can use Burp Suite's Clickbandit:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-2/images/Pasted%20image%2020230102051214.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-2/images/Pasted%20image%2020230102051223.png)

- Copy Clickbandit to clipboard:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-2/images/Pasted%20image%2020230102051948.png)

- Paste it to developer tool:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-2/images/Pasted%20image%2020230102052357.png)

- Click "Start":

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-2/images/Pasted%20image%2020230102052413.png)

- Click the "Update email" button:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-2/images/Pasted%20image%2020230102052435.png)

- Click "Finish":

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-2/images/Pasted%20image%2020230102052509.png)

- Click "Save": (**Remember to turn off transparency**)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-2/images/Pasted%20image%2020230102053313.png)

**Downloaded Proof-of-Concept clickjacking HTML file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-2/images/Pasted%20image%2020230102053332.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-2/images/Pasted%20image%2020230102053358.png)

**Finally, go to the exploit server, host the file and deliver to victim:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-2/images/Pasted%20image%2020230102053438.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-2/images/Pasted%20image%2020230102053446.png)

Nice!

# What we've learned:

1. Clickjacking with form input data prefilled from a URL parameter