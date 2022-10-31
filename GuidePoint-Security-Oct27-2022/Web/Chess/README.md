# Chess

## Overview

- Overall difficulty for me: Easy

**In this challenge, we can spawn a docker instance:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029002013.png)

## Find the flag

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029002041.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029002048.png)

**Let's see how this chess game works by viewing their JavaScript!**
```html
<script type="text/ecmascript" src="chess.js"></script>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029002450.png)

Hmm... The `StormCTF*` variables look sussy.

> Note: I tried to deobfuscate that, but no luck.

Let's take step back.

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029003513.png)

**In here, we can download a sample PGN file:**
```
┌──(root🌸siunam)-[~/ctf/GuidePoint-Security-Oct27-2022/Web/Chess]
└─# cat /home/nam/Downloads/sample.pgn 
[Event "ICS Unrated Chess Match"]
[Site "?"]
[Date "2010.07.18"]
[Round "?"]
[White "GuestSXJG"]
[Black "GuestRBZS"]
[TimeControl "300+0"]
[Result "1-0"]

1. e4 e6 2. d4 g6 3. d5 Bg7 4. dxe6 fxe6 5. Nf3 Ne7 6. Bg5 c6 7. e5 Qa5+ 
8. Qd2 Qb6 9. Bxe7 Kxe7 10. Qg5+ Ke8 11. b3 Rf8 12. Bd3 d6 13. c3 dxe5 
14. Nxe5 Qxf2+ 15. Kd1 Bxe5 16. Qxe5 Qxg2 17. Be4 Rf1+ 18. Rxf1 Qxf1+ 19. Kc2 
Nd7 20. Qh8+ Qf8 21. Qxh7 Ne5 22. Nd2 Bd7 23. Nc4 Qf2+ 24. Nd2 Rd8 25. Rf1 
Qe3 26. Bxg6+ Nxg6 27. Qf7# 
{GuestRBZS checkmated} 1-0
```

**How about we upload and load this file??**

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029003618.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029003643.png)

We got the flag!

# Conclusion

What we've learned:

1. Uploading File in a Web page?