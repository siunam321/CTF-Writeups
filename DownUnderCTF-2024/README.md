# DownUnderCTF 2024 Writeup

> CTFTime event link: [https://ctftime.org/event/2284](https://ctftime.org/event/2284)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/banner.png)

## Background

- Starts: 05 July 2024, 09:30 UTC
- Ends: 07 July 2024, 09:30 UTC

DownUnderCTF is the largest online Australian-run Capture The Flag (CTF) competition, now welcoming Aotearoa (New Zealand) to the competition for the first time in 2024. With over 4200+ registered users and more than 2000+ registered teams as of 2023, its primary goal is to up-skill the next generation of potential Cyber Security Professionals and to expand the CTF community in Australia and Aotearoa (New Zealand). While our CTF is an online event open to participants worldwide, starting from 2024, prize eligibility extends to include both Australian and Aotearoa (New Zealand) Secondary or Tertiary school students. This change aims to foster a closer collaboration and competition spirit between the two nations while maintaining our commitment to enhancing cybersecurity skills among the youth.

**Categories:**

- beginner
- crypto
- pwn
- web
- rev
- hardware
- misc
- forensics
- osint

## Overview

- Team: [NuttyShell](https://polyuctf.com/)
- Team Solves: 27/66
- Individual Solves: 7/66
- Score: 3211/15223
- Global Rank: 73/2176
- Overall Difficulty To Me: ★★★★☆☆☆☆☆☆

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/certificate.png)

## What I've learned in this CTF

- web (beginner)
    1. [parrot the emu](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/web/parrot-the-emu/README.md) - Server-Side Template Injection (SSTI) in Jinja
    2. [zoo feedback form](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/web/zoo-feedback-form/README.md) - XML External Entity (XXE) injection (First blooded)
- web
    1. [co2](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/web/co2/README.md) - Python class pollution
    2. [co2v2](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/web/co2v2/README.md) - Stored XSS and CSP bypass via Python class pollution
    3. [i am confusion](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/web/i-am-confusion/README.md) - JSON Web Token (JWT) algorithm confusion
    4. [sniffy](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/web/sniffy/README.md) - File MIME type filter bypass