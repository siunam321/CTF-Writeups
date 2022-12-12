# Unprotected admin functionality with unpredictable URL

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality-with-unpredictable-url), you'll learn: Unprotected admin functionality with unpredictable URL! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab has an unprotected admin panel. It's located at an unpredictable location, but the location is disclosed somewhere in the application.

Solve the lab by accessing the admin panel, and using it to delete the user `carlos`.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-2/images/Pasted%20image%2020221212042522.png)

**In the previous lab, we found an admin panel via `robots.txt`, let's do the same thing again:**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Access-Control/AC-2]
└─# curl https://0a4f006f0487ca37c0a0910b00450047.web-security-academy.net/robots.txt
curl: (52) Empty reply from server
```

Hmm... The file doesn't exist.

**Let's view the source page:**
```html
[...]
<section class="top-links">
   <a href=/>Home</a><p>|</p>
   <script>
      var isAdmin = false;
      if (isAdmin) {
      var topLinksTag = document.getElementsByClassName("top-links")[0];
      var adminPanelTag = document.createElement('a');
      adminPanelTag.setAttribute('href', '/admin-fnrrou');
      adminPanelTag.innerText = 'Admin panel';
      topLinksTag.append(adminPanelTag);
      var pTag = document.createElement('p');
      pTag.innerText = '|';
      topLinksTag.appendChild(pTag);
      }
   </script>
   <a href="/my-account">My account</a><p>|</p>
</section>
[...]
```

**We can see something interesting here:**

- When we click the `Home` link, it'll run a JavaScript code:
	- **If `isAdmin` is `true`, it creates a new link with the `Admin panel`, and the location is: `/admin-fnrrou`!**

**Armed with above information, we can just go there!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-2/images/Pasted%20image%2020221212043017.png)

Now, we can delete user `carlos`!!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-2/images/Pasted%20image%2020221212043036.png)

# What we've learned:

1. Unprotected admin functionality with unpredictable URL