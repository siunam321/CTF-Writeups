# Authentication bypass via encryption oracle

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-authentication-bypass-via-encryption-oracle), you'll learn: Authentication bypass via encryption oracle! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Background

This lab contains a logic flaw that exposes an encryption oracle to users. To solve the lab, exploit this flaw to gain access to the admin panel and delete Carlos.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-11/images/Pasted%20image%2020221221013810.png)

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-11/images/Pasted%20image%2020221221013832.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-11/images/Pasted%20image%2020221221013844.png)

**We also see that users can stay logged in:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-11/images/Pasted%20image%2020221221014951.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-11/images/Pasted%20image%2020221221015056.png)

After logged in, **a new cookie called `stay-logged-in` has been set.**

Hmm... Is there any way to **decrypt** that cookie value?

**After poking around the web site, I found something interesting:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-11/images/Pasted%20image%2020221221020012.png)

In all posts, users can leave comments.

**Let's take a look at the HTML form:**
```html
<form action="/post/comment" method="POST" enctype="application/x-www-form-urlencoded">
	<input required type="hidden" name="csrf" value="xMBJcQT8l3tlo2jTAMnr78eLKCi1p7tG">
	<input required type="hidden" name="postId" value="3">
	<label>Comment:</label>
	<textarea required rows="12" cols="300" name="comment"></textarea>
		<label>Name:</label>
		<input required type="text" name="name">
		<label>Email:</label>
		<input required name="email">
		<label>Website:</label>
		<input pattern="(http:|https:).+" type="text" name="website">
	<button class="button" type="submit">Post Comment</button>
</form>
```

As you can see, only the website field is not required.

**Let's try to leave some comments and intercept the request via Burp Suite's Repeater:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-11/images/Pasted%20image%2020221221020307.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-11/images/Pasted%20image%2020221221020340.png)

When we send a valid request, it'll redirect user to `/post/comment/confirmation`.

**What if I send an invalid email address?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-11/images/Pasted%20image%2020221221020447.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-11/images/Pasted%20image%2020221221020703.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-11/images/Pasted%20image%2020221221020829.png)

Hmm... **It sets a new cookie called `notification` with the value `ycMDfGd+EeDEELbDeBeS4BVDt1b3I/KCv4J7nKoqQK4=`.**

**Also, our invalid email address is reflected, and it's in cleartext!**

**How about we copy and paste our `stay-logged-in` cookie value to `notification`? Will it decrypt that for us?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-11/images/Pasted%20image%2020221221021345.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-11/images/Pasted%20image%2020221221021356.png)

Nice! We successfully decrypted the `stay-logged-in` cookie value: `wiener:1671605400893`. (Format = username:timestamp)

**Now, what if I change the username to `administrator`, and then encrypt it again?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-11/images/Pasted%20image%2020221221021631.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-11/images/Pasted%20image%2020221221021710.png)

Now we got this: `ycMDfGd+EeDEELbDeBeS4Er1WSkgQ7spte2Y+njPwnl0IabAFW7NPOIMFq5bBkaWLquEcOGzExJqmfnGAbyLVg==`

However, the `notification` automatically added `Invalid email address: ` to the cookie.

How do we get rid of it?

**First, let's find how long is that string:**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-11]
└─# echo -n "Invalid email address: " | wc -m
23
```

It's **23** characters long.

**Then, we can remove those characters.**

**To do so, I'll use [CyberChef](https://gchq.github.io/CyberChef/):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-11/images/Pasted%20image%2020221221023603.png)

**Let's copy that encoded output and paste it to the `notification` cookie!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-11/images/Pasted%20image%2020221221023653.png)

Hmm... **The cookie value length must be multiple of 16.**

**Let's go back to CyberChef and check the length of the decoded output:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-11/images/Pasted%20image%2020221221024002.png)

So our decoded output length is 41.

**Let's add more 9 characters to the encrypted cookie, and then we drop more 9 bytes: (41 - 9 = 32, 16 * 2 = 32)**

**New fake email address:**
```
AAAAAAAAAadministrator:1671605400893
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-11/images/Pasted%20image%2020221221024421.png)

**New notification cookie: `ycMDfGd%2bEeDEELbDeBeS4Mdq3E%2bq7mjgMCKdjP0CVsIV8SyZ8Hkkar6g1sygpS3rK%2fuJO8LuYHhCDctNIeATKQ%3d%3d`**

**In CyberChef, update Drop bytes recipe's length to 32:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-11/images/Pasted%20image%2020221221024547.png)

**Now let's copy and paste that encoded output to our `notification` cookie, so that the application will decrypt it for us:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-11/images/Pasted%20image%2020221221024630.png)

**Nice! In here, let's copy and paste the `notification` cookie to `stay-logged-in` cookie, and delete `session` cookie!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-11/images/Pasted%20image%2020221221024824.png)

**Now refresh the page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-11/images/Pasted%20image%2020221221024842.png)

**Boom! We see the admin panel, let's access to that!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-11/images/Pasted%20image%2020221221024902.png)

We now can delete user `carlos`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-11/images/Pasted%20image%2020221221024920.png)

We did it!

# What we've learned:

1. Authentication bypass via encryption oracle