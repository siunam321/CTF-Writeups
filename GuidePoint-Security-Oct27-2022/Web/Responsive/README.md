# Responsive

## Overview

- Overall difficulty for me: Medium

**In this challenge, we can spawn a docker instance:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029004634.png)

## Find the flag

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029004710.png)

We're prompt to a login page!

**We can try to guess the username and password:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029004943.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029005021.png)

Hmm... No luck.

If you look carefully in the header: **`No Login`, and a login prompt.**

This got me thinking: **Is this about NoSQL injection authentication bypass??**

**According to [this blog](https://www.varutra.com/nosql-injection-vulnerability/), we can bypass it via `[$ne]`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029012047.png)

**Let's fire up Burp Suite and capture the POST request!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029012114.png)

**Modify the POST value and forward the request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029012139.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029012210.png)

We're in!

# Conclusion

What we've learned:

1. Authentication Bypass via NoSQL Injection