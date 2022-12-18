# Hashstation

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

- Challenge difficulty: Easy

## Background

Author: @JohnHammond#6971  
  
Below is a [SHA256](https://en.wikipedia.org/wiki/SHA-2) hash! Can you determine what the original data was, before it was hashes?  
  
`705db0603fd5431451dab1171b964b4bd575e2230f40f4c300d70df6e65f5f1c`  
  
**Please wrap the original value within the `flag{` prefix and `}` suffix to match the standard flag format.**

## Find The Flag

According to the challenge's title, it's clear that **the title is referring to [CrackStation](https://crackstation.net/)! Which is an online tool that lookup all different hashes.**

**Let's throw that SHA256 hash to CrackStation!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-EU-CTF-2022/images/Pasted%20image%2020221216222508.png)

Found it!

- **Flag: `flag{awesome}`**

# Conclusion

What we've learned:

1. Cracking SHA256 Hash via [CrackStation](https://crackstation.net/)