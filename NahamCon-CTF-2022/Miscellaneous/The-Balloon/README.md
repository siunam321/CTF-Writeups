# Background
![background](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Miscellaneous/The-Balloon/images/background.png)

As usual, let's download the `theballoon` file and see what it is.

![question](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Miscellaneous/The-Balloon/images/question.png)

It's said it's **defalted balloon(Compressed data)**, `spin it around`, `_inflate_ it`. Then, I saw a string that's rotated, and it reminds me Cicada 3301 stuff, as it looks a `HTTPS scheme`. Hmm... Let's use [CyberChef](https://gchq.github.io/CyberChef/) to rotate that string. I'll use `Rot13` recipe and manully change the `amount`.

![solution1](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Miscellaneous/The-Balloon/images/solution1.png)

Oh... It's a pastebin link. Let's check that out.

![solution2](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Miscellaneous/The-Balloon/images/solution2.png)

Weird string... Let's throw that into CyberChef again with the `Raw Inflate` recipe, as the `theballoon` file tells us to **inflate it(Decompress).**

![flag](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Miscellaneous/The-Balloon/images/flag.png)

And voila!! That's the flag!