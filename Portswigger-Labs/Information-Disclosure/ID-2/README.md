# Information disclosure on debug page

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-on-debug-page), you'll learn: Information disclosure in error messages! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a debug page that discloses sensitive information about the application. To solve the lab, obtain and submit the `SECRET_KEY` environment variable.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Information-Disclosure/ID-2/images/Pasted%20image%2020221216052826.png)

**Let's view the source page!**
```html
	</div>
</section>
<!-- <a href=/cgi-bin/phpinfo.php>Debug</a> -->
```

**Oh look! We found an interesting HTML comment tag! Which is an `<a>` tag that pointing to PHP info page!**

**Let's go there:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Information-Disclosure/ID-2/images/Pasted%20image%2020221216053016.png)

**In the `Environment` session, we found a `SECRET_KEY`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Information-Disclosure/ID-2/images/Pasted%20image%2020221216053033.png)

# What we've learned:

1. Information disclosure on debug page