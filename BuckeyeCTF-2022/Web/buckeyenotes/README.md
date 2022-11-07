# buckeyenotes

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

> Note taking apps are all the rage lately but turns our they're harder to make than I thought :/. Even in development buckeyenotes has gotten some traction, Brutus signed up! I think his user name is brutusB3stNut9999. I wonder what kind of notes he writes 🤔 but I don't have his login....

[https://buckeyenotes.chall.pwnoh.io](https://buckeyenotes.chall.pwnoh.io)

> Author: rene

> Difficulty: Beginner

## Find the flag

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221104210137.png)

We're prompt to a login page.

In the challenge description, **we know Brutus's username: `brutusB3stNut9999`. But we don't know his password!**

Let's test for a login attemp!

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221104210333.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221104210341.png)

We got `Invalid username or password`.

Whenever I deal with login page, I always try to do a **SQL injection authenication bypass**.

**Let's try a simple `' OR 1=1-- -` payload!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221104210504.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221104210510.png)

`nice try, hacker >:D I removed your equal signs`?

Looks like there has some filtering going on.

Hmm... **What if I put that payload to the username field?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221104210608.png)

Logged in as `rene`. Nothing posted yet :(

Hmm... There is a username called `rene`??

I tried to use Brutus's username as rene's password, but no dice.

Let's go back to Brutus.

Armed with above information, **we need to login as `brutusB3stNut9999` via SQL injection**.

**Now, in order to bypass the `=` filter, we can just don't use `=`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105073118.png)

**Then, since we're retrieving the first record in the database, which is rene's password, we need to retrieve the second record, which is Brutus's password!**

**To do so, I'll use the `LIMIT` clause:**
```
' OR 1 LIMIT 1, 2-- -
```

This will only show 1 record in the second record.

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105073328.png)

We got the flag!

# Conclusion

What we've learned:

1. SQL Injection & Bypass