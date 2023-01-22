# Logger

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

- Challenge static score: 100

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121135147.png)

## Find the flag

**In the challenge's description, we can download an attachment. Let's download it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121135214.png)

```shell
┌[root♥siunam]-(~/ctf/KnightCTF-2023/Misc/Logger)-[2023.01.21|13:52:22(HKT)]
└> file misc-access.log 
misc-access.log: CSV text

┌[root♥siunam]-(~/ctf/KnightCTF-2023/Misc/Logger)-[2023.01.21|13:52:33(HKT)]
└> head -n 5 misc-access.log 
2023-01-03 15:45:57.285679 - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 - GET /- - 34760
2023-01-03 15:46:01.758679 - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 - GET /e - 3952
2023-01-03 15:46:13.155679 - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 - GET /6 - 61534
2023-01-03 15:46:05.193679 - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 - GET /h - 47571
2023-01-03 15:46:13.851679 - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 - GET /! - 2882

┌[root♥siunam]-(~/ctf/KnightCTF-2023/Misc/Logger)-[2023.01.21|13:53:13(HKT)]
└> wc -l misc-access.log 
9999 misc-access.log
```

As you can see, it's an HTTP access log, and it has 10000 request logs.

Hmm... If we can **sort the date in ascending order**, that might be helpful for us.

**To do so, we can use Linux command `sort`:**
```shell
┌[root♥siunam]-(~/ctf/KnightCTF-2023/Misc/Logger)-[2023.01.21|14:03:44(HKT)]
└> cat misc-access.log | sort > misc-access-sorted.log
```

```shell
┌[root♥siunam]-(~/ctf/KnightCTF-2023/Misc/Logger)-[2023.01.21|14:04:51(HKT)]
└> tail -n 21 misc-access-sorted.log
2023-01-03 15:46:20.382679 - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 - GET /K - 39950
2023-01-03 15:46:20.385679 - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 - GET /C - 6142
2023-01-03 15:46:20.388679 - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 - GET /T - 48333
2023-01-03 15:46:20.391679 - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 - GET /F - 16796
2023-01-03 15:46:20.394679 - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 - GET /{ - 45424
2023-01-03 15:46:20.397679 - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 - GET /w - 57044
2023-01-03 15:46:20.400679 - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 - GET /r - 56376
2023-01-03 15:46:20.403679 - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 - GET /1 - 34061
2023-01-03 15:46:20.406679 - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 - GET /n - 18217
2023-01-03 15:46:20.409679 - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 - GET /k - 13820
2023-01-03 15:46:20.412679 - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 - GET /l - 3610
2023-01-03 15:46:20.415679 - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 - GET /3 - 43593
2023-01-03 15:46:20.418679 - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 - GET /_ - 46224
2023-01-03 15:46:20.421679 - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 - GET /1 - 49001
2023-01-03 15:46:20.424679 - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 - GET /n - 5135
2023-01-03 15:46:20.427679 - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 - GET /_ - 42868
2023-01-03 15:46:20.430679 - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 - GET /7 - 51928
2023-01-03 15:46:20.433679 - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 - GET /1 - 42167
2023-01-03 15:46:20.436679 - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 - GET /m - 9672
2023-01-03 15:46:20.439679 - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 - GET /3 - 13974
2023-01-03 15:46:20.442679 - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 - GET /} - 5898
```

Now we can find the flag!!

**Let's write a simple python script to find the flag:**
```py
#!/usr/bin/env python3

flag = ''

with open('misc-access-sorted.log', 'r') as file:
    for line in file:
        flag += line.strip()[148:149]

print(flag)
```

```shell
┌[root♥siunam]-(~/ctf/KnightCTF-2023/Misc/Logger)-[2023.01.21|14:12:00(HKT)]
└> python3 solve.py
[...]KCTF{wr1nkl3_1n_71m3}
```

Found it!

- **Flag: `KCTF{wr1nkl3_1n_71m3}`**

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121141355.png)

# Conclusion

What we've learned:

1. Sorting HTTP Access Log By Time