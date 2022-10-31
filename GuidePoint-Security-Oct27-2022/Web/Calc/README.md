# Calc

## Overview

- Overall difficulty for me: Medium

**In this challenge, we can start a docker instance:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221027085615.png)

## Find the flag

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221027085647.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221027085713.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221027085723.png)

**As you can see, we can do calcalation in here.**

**Hmm... Looks like we can do something weird to the GET parameter?**

Maybe it's vulnerable to **command injection**??

**According to [HackTricks](https://book.hacktricks.xyz/pentesting-web/command-injection#command-injection-execution), we can use this payload:**
```
ls %0A id # %0A Execute both (RECOMMENDED)
```

> Note: `%0A` means new line character in URL encoding.

Let's test this payload!

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221028071059.png)

It works!

**The `calchdeyenbdw7wjh281y1hd771ujs718hq.txt` file looks weird to me, let's `cat` that file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221028071201.png)

We found the flag!

# Conclusion

What we've learned:

1. Exploiting Command Injection