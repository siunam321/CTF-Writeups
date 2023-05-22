# Fetus Web

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Find the flag](#find-the-flag)
4. [Conclusion](#conclusion)

## Overview

- 368 solves / 50 points
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

A simple web warmup.

- Junhua

[http://34.124.157.94:12325](http://34.124.157.94:12325)

## Find the flag

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/images/Pasted%20image%2020230519220330.png)

**View source page:**
```html
[...]
      <!-- End Services Section -->

      <!-- Flag part 1: grey{St3p_1-->

      <!-- ======= Counter Section ======= -->
[...]
```

In here, we see the first part of the flag: `grey{St3p_1`

**Then, we can open up "Debugger" tab to find the second part:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/images/Pasted%20image%2020230519220454.png)

- **Full flag: `grey{St3p_1_of_b4by_W3b}`**

## Conclusion

What we've learned:

1. Inspecting Source Page