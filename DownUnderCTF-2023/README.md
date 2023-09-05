# DownUnderCTF 2023 Writeup

> CTFTime event link: [https://ctftime.org/event/1954](https://ctftime.org/event/1954)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/banner.png)

## Background

- Starts: 01 September 2023, 17:30 HKT
- Ends: 03 September 2023, 17:30 HKT

DownUnderCTF is the largest online Australian run Capture The Flag (CTF) competition with over 4100+ registered users and over 1900+ registered teams (2022). Its main goal is to try to up-skill the next generation of potential Cyber Security Professionals and increase the CTF community's size here in Australia. Prizes are only for Australian Secondary or Tertiary school students. However, our CTF is online and open for anyone to play worldwide.

**Categories:**

- crypto
- pwn
- web
- rev 
- misc
- blockchain
- osint

## Overview

- Team: [ARESx](https://ctftime.org/team/128734)
- Team Solves: 27/68
- Individual Solves: 10/68
- Score: 3075/14341
- Rank: 92/2110
- Overall Difficulty To Me: ★★★★★☆☆☆☆☆

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/cert.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/solves.png)

## What I've learned in this CTF

- misc:
    1. Python built-in function `help()` shell escape ([helpless](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/misc/helpless/README.md))
- osint:
    1. Extracting image's metadata via `exiftool` ([Excellent Vista!](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/osint/Excellent-Vista!/README.md))
    2. Reverse image search ([Bridget's Back!](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/osint/Bridget's-Back!/README.md), [Comeacroppa](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/osint/Comeacroppa/README.md))
- web:
    1. Proxying via `X-Forwarded-For` header ([proxed](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/web/proxed/README.md))
    2. Exploiting path traversal vulnerability ([static file server](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/web/static-file-server/README.md))
    3. Exploiting file upload vulnerability with 16 characters chunk ([xxd-server](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/web/xxd-server/README.md))
    4. Double proxying via `X-Forwarded-For` header ([actually-proxed](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/web/actually-proxed/README.md))
    5. Sign arbitrary JWT via flawed signing process ([grades_grades_grades](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/web/grades_grades_grades/README.md))
    6. Exploiting Perl's `param()` flaw ([cgi fridays](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/web/cgi-fridays/README.md))