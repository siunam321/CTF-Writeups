# pocket-monsters

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★★★★★☆☆☆

> Something happened to my save and now my game won't run :sadge: all my precious Pokemon are gone :sob: please help...

Flag format: buckeye(...)

> Author: gsemaj

> Difficulty: Medium

## Find the flag

**In this challenge, we can download a file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221106033217.png)

```
┌──(root🌸siunam)-[~/ctf/BuckeyeCTF-2022/Misc/pocket-monsters]
└─# file pocket-monsters.sav         
pocket-monsters.sav: data
```

After some googling, this `.sav` extension is a **Pokemon save file**!

**Let's transfer this file to my Windows 10 virutal machine!**
```
┌──(root🌸siunam)-[~/ctf/BuckeyeCTF-2022/Misc/pocket-monsters]
└─# python3 -m http.server 80     
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

PS C:\Users\Student\Desktop> Invoke-WebRequest -Uri http://192.168.183.141/pocket-monsters.sav -OutFile .\pocket-monsters.sav
```

**Now, we can download a tool that allow us to modify the save file via [PKHeX](https://projectpokemon.org/home/files/file/1-pkhex/):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221106033757.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221106033809.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221106033817.png)

In here, we can see a box that fills with lots of Pokemons.

**Let's dump them!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221106033954.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221106034020.png)

**Then, we can view the PKM database:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221106034057.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221106034205.png)

**In here, we can also create a data report:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221106034229.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221106034317.png)

Hmm... The all of the pokemon's nickname looks like the flag!

Flag: `buckeye(90774-3mu1473-3m-411)`

# Conclusion

What we've learned:

1. Reversing Pokemon Save File??