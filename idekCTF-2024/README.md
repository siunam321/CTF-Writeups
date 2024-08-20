# idekCTF 2024 Writeup

> CTFTime event link: [https://ctftime.org/event/2304](https://ctftime.org/event/2304)

![](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2024/images/banner.png)

## Background

- Starts: 17 Aug. 2024, 00:00 UTC
- Ends: 19 Aug. 2024, 00:00 UTC

idekCTF is an information security CTF competition organized by the idek team and is aimed at the entire spectrum from high school and university students to experienced players. idekCTF will cover the standard Jeopardy-style CTF topics (binary exploitation, reverse engineering, cryptography, web exploitation, and forensics) as well as other, less standard categories. 

**Categories:**

- crypto
- misc
- pwn
- rev
- sanity
- web

## Overview

- Team: [ARESx](https://ctftime.org/team/128734)
- Team Solves: 6/35
- Individual Solves: 2/35
- Score: 1099
- Global Rank: 70/1070
- Overall Difficulty To Me: ★★★★★★★★★☆

![](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2024/images/score.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2024/images/solves.png)

## What I've learned in this CTF

- web
    1. [Hello](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2024/web/Hello/README.md) - Reflect XSS and exfiltrating `httpOnly` cookies via Nginx misconfiguration and PHP `phpinfo()`
    2. [crator](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2024/web/crator/README.md) - Race condition to read removed files