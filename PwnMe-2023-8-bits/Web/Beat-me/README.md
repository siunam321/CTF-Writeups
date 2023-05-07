# Beat me!

## Table of Contents

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

## Overview

- 101 solves / 50 points
- Difficulty: Medium
- Overall difficulty for me (From 1-10 stars): ★★★★★★☆☆☆☆

## Background

> Author: Eteck#3426

A pro player challenge you to a new game. He spent a huge amount of time on it, and did an extremely good score.

Your goal is to beat him.. by any way

_If the game doesn't start, try an other nagivator_

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506201325.png)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506201352.png)

In here, we can type our name to play a spaceshooter client-side game.

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506201430.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506201446.png)

After the game has ended, it'll send a POST request to `/scores`, with JSON data:

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506201517.png)

Since the challenge has a tag called "client-side game", ***I wonder if we can control the `signature` key's value.***

**Now, let's try to modify it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506201655.png)

Nope. So the back-end must checking the signature is correct or not.

**That being said, let's try to read the source code of the game:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506201813.png)

Oh boi... It's **obfuscated**...

**Umm... Let's search for `signature`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506202118.png)

Found it!

**Then, I set some breakpoint in the for loop, and trigger the breakpoint by ending the game:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506202210.png)

Hmm?? `00bfuScat3d_K3y`?

What this for loop does is to **hash something? with the `00bfuScat3d_K3y` salt**. The `_0x8a3192`'s output is the correct `signature`.

However, I tried to copy and paste that for loop statement to generate the same `signature`, but no dice...

**Also, there is a big long list of array:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506204008.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506204036.png)

In that array, we can see there is a method called `setScore()`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506204111.png)

Again, I tried to find where does this method is being called, no luck.

## Exploitation

At this point, **I'm trying to control the score, so that the hashing for loop statement will generate the correct `signature`.**

**Now, we can set a breakpoint when the hashing statement's function is invoked:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506221811.png)

**Then, gain some points and end the game:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506221839.png)

As expected, we hit the breakpoint.

Next, I noticed that the `_0x359a29` variable's value is `2`, which is the current game state's score.

**Hmm... Can I access that variable in the "Console" tab during the breakpoint??**

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506222017.png)

Wait, I can? I never seen this before!!

That being said, we can modify `_0x359a29`'s value in the "Console" tab!!

**Since the challenge's description says "Your goal is to beat him.. by any way". Let's update the score to `1337421`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506222224.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506222248.png)

As you can see, it's updated!

**Let's click the "Resume" button to finish the breakpoint:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506222330.png)

**Then, in the Burp Suite HTTP history, we should see a response with "Invalid signature":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506222403.png)

Finally, send that request to Repeater, and ***change the `score` key's value to `1337421`***:

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506222444.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506222519.png)

Boom!! We successfully beat the pro player, and got the flag!

- **Flag: `PWNME{Ch3a7_0n_Cl1en7_G4m3_Is_n0T_H4rD_87}`**

## Conclusion

What we've learned:

1. Deobfuscating JavaScript Code & Exploiting Client-Side Game