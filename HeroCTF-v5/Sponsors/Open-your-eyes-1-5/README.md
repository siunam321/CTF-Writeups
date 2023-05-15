# Open your eyes 1/5

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Find the flag](#find-the-flag)
4. [Conclusion](#conclusion)

## Overview

- 74 solves / 261 points
- Difficulty: Easy
- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

Sometimes there is more than meets the eye. Be clever and collect the 5 flags. Some are easy, some are hard.

Access the challenge here : [https://heroctf.joinopencyber.tech/](https://heroctf.joinopencyber.tech/)  
Format : Hero{J...}  
Author : OPENCYBER

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230514182030.png)

## Find the flag

**In this challenge, we can access the challenge machine in [https://heroctf.joinopencyber.tech/](https://heroctf.joinopencyber.tech/):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230514182107.png)

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230514182118.png)

In here, we can "LOGIN AS A GUEST" or "LOGIN".

**Let's login as a guest first:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230514182204.png)

In here, we can send some messages to someone.

Since **JavaScript is a client-side language**, we can poke around in the source code.

**To do so, I'll open up the "Debugger" tab:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230514182331.png)

As you can see, **it has 2 main JavaScript files: `app.js`, `main.js`.**

**But before we look at the `main.js`, I found something weird in `app.js`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230514182459.png)

Hmm... I can see the flag format! (`Hero{.*}`)

Now, we can **dynamically deobfuscate** those JavaScript code!

> Note: You can read my recent "PwnMe Qualifications : “8 bits”"'s web challenge writeup: [Beat me!](https://siunam321.github.io/ctf/PwnMe-2023-8-bits/Web/Beat-me/). It's a web challenge that exploiting client-side game and dynamically deobfuscating JavaScript code.

**That being said, let's add a breakpoint to variable `_0x2e08e0`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230514182725.png)

**Then refresh the page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230514182741.png)

**Next, click the "Step Over" button twice:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230514182809.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230514182831.png)

Nice! We found half of the flag: 

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230514182912.png)

However, we can't step over again, as the if statement in line 31 won't get passed.

**If you look closely, variable `_0x45a81e` is function `_0x4cbad0()`:** 

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230514183039.png)

**So, we can concatenate the full flag via variable `_0x45a81e`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230514183140.png)

- **Flag: `Hero{J@v@Scr!pt_f!l3s_R_alway$_Nic3_t0_Gr@b}`**

## Conclusion

What we've learned:

1. Dynamically Deobfuscating JavaScript Code