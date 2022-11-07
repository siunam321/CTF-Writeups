# textual

## Overview

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

> I made a LaTeX to HTML converter. Why? Because I believe in more than WYSIWYG. Don't worry though, it's totally safe!

[https://textual.chall.pwnoh.io](https://textual.chall.pwnoh.io)

> Author: v0rtex

> Difficulty: Beginner

## Find the flag

**In this challenge, we can download a file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105015413.png)

```
┌──(root🌸siunam)-[~/ctf/BuckeyeCTF-2022/Web/textual]
└─# file textual.zip 
textual.zip: Zip archive data, at least v1.0 to extract, compression method=store
                                                                                                           
┌──(root🌸siunam)-[~/ctf/BuckeyeCTF-2022/Web/textual]
└─# unzip textual.zip          
Archive:  textual.zip
   creating: static/
   creating: static/stylesheets/
  inflating: static/stylesheets/main.css  
  inflating: static/index.html       
  inflating: Dockerfile              
  inflating: docker-compose.yml      
  inflating: index.js                
  inflating: jail.cfg                
  inflating: package-lock.json       
  inflating: package.json            
  inflating: run.sh                  
  inflating: flag.tex
```

**`flag.tex`:**
```
┌──(root🌸siunam)-[~/ctf/BuckeyeCTF-2022/Web/textual]
└─# cat flag.tex 
\documentclass{article}

\title{BuckeyeCTF 2022}
\author{v0rtex}
\date{November, 2022}

\begin{document}

\maketitle

\section{The challenge}
Nobody is ever going to be able to see this document, so it's a good thing I decided to hide the flag in here! $buckeye{this_is_a_fake_flag}$
\end{document}
```

Looks like we need to `cat` this file to get the flag.

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105015859.png)

**Hmm... LaTeX to HTML. Let's google about `LaTeX exploit`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105020019.png)

This [blog](https://0day.work/hacking-with-latex/) looks good for us:

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105020104.png)

**Now, since we know the flag file is `flag.tex`, we can use this payload to extract it!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105020141.png)

We got the flag!

# Conclusion

What we've learned:

1. Exploiting LaTeX