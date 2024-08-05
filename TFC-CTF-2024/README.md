# TFC CTF 2024 Writeup

> CTFTime event link: [https://ctftime.org/event/2423](https://ctftime.org/event/2423)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TCTF-CTF-2024/images/banner.png)

## Background

- Starts: 02 Aug. 2024, 11:00 UTC
- Ends: 04 Aug. 2024, 11:00 UTC

This year, The Few Chosen are thrilled to host our fourth annual Capture The Flag (CTF) event, set to take place from August 2nd to 4th, 2024.

We, a committed team of cyber enthusiasts who've cut our teeth on countless CTFs, are channelling our passion for cybersecurity into curating this unique, immersive CTF experience. We've meticulously engineered the event's website from scratch, ensuring a seamless and enriching user experience. Our diverse set of challenges spans Pwn, Reverse, Web, Crypto, and Misc, each graded from "Warmup" to "Hard".

This deliberate spectrum of difficulty ensures our CTF event is universally accessible - from cybersecurity novices eager to learn the ropes, to seasoned experts looking to flex their skills in a challenging environment. Mark your calendars for a uniquely immersive cybersecurity adventure. The Few Chosen CTF 2024: The perfect platform for honing skills, fueling passions, and embracing the cybersecurity community.

**Categories:**

- Crypto
- Pwn
- Web
- Misc
- Reverse
- Forensics

## Overview

- Team: [NuttyShell](https://polyuctf.com/)
- Team Solves: 16/41
- Individual Solves: 7/41
- Score: 2944
- Global Rank: 24/1478
- Overall Difficulty To Me: ★★★★★☆☆☆☆☆

![](https://github.com/siunam321/CTF-Writeups/blob/main/TCTF-CTF-2024/images/score.png)

## What I've learned in this CTF

- Web
    1. [GREETINGS](https://github.com/siunam321/CTF-Writeups/blob/main/TCTF-CTF-2024/Web/GREETINGS/README.md) - PugJs Server-Side Template Injection (SSTI)
    2. [SURFING](https://github.com/siunam321/CTF-Writeups/blob/main/TCTF-CTF-2024/Web/SURFING/README.md) - Open redirect in Google Accelerated Mobile Pages (AMP) to Server-Side Request Forgery
    3. [SAFE_CONTENT](https://github.com/siunam321/CTF-Writeups/blob/main/TCTF-CTF-2024/Web/SAFE_CONTENT/README.md) - PHP function `parse_url` host filter bypass via `data` URI scheme, blind OS command injection
    4. [FUNNY](https://github.com/siunam321/CTF-Writeups/blob/main/TCTF-CTF-2024/Web/FUNNY/README.md) - Apache CGI misconfiguration to Remote Code Execution (RCE)
    5. [SAGIGRAM](https://github.com/siunam321/CTF-Writeups/blob/main/TCTF-CTF-2024/Web/SAGIGRAM/README.md) - Large Language Model (LLM) prompt injection to stored XSS chained with CSP bypass