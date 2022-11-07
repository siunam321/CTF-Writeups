# sus

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★★★★☆☆☆☆

> Something about this audio is pretty _sus_...

> Author: gsemaj

> Difficulty: Easy

## Find the flag

**In this challenge, we can download a file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105061323.png)

```
┌──(root🌸siunam)-[~/ctf/BuckeyeCTF-2022/Misc/sus]
└─# file sus.wav 
sus.wav: RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, mono 48000 Hz
```

Hmm... A sound file.

**Let's fire up Audacity to find anything weird:**
```
┌──(root🌸siunam)-[~/ctf/BuckeyeCTF-2022/Misc/sus]
└─# audacity sus.wav
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105061428.png)

**Nothing weird here. Let's switch to `Spectrogram` mode:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105061521.png)

Still no dice.

**Then, after I banging my head against the wall, I googled about audio steganography:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105061654.png)

Let's look at this [Medium blog](https://sumit-arora.medium.com/audio-steganography-the-art-of-hiding-secrets-within-earshot-part-2-of-2-c76b1be719b3)!

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105061738.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105061745.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105061755.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105061834.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105061841.png)

Hmm... Using LSB algorithm to hide hidden messages??

**Let's copy and paste that `receiver.py` to our attacker machine!**
```py
#!/usr/bin/env python3

import wave
song = wave.open("sus.wav", mode='rb')
# Convert audio to byte array
frame_bytes = bytearray(list(song.readframes(song.getnframes())))

# Extract the LSB of each byte
extracted = [frame_bytes[i] & 1 for i in range(len(frame_bytes))]
# Convert byte array back to string
string = "".join(chr(int("".join(map(str,extracted[i:i+8])),2)) for i in range(0,len(extracted),8))
# Cut off at the filler characters
decoded = string.split("###")[0]

# Print the extracted text
print("Sucessfully decoded: "+decoded)
song.close()
```

**Run that script!**
```
┌──(root🌸siunam)-[~/ctf/BuckeyeCTF-2022/Misc/sus]
└─# python3 solve.py
Sucessfully decoded: buckeye{4y000_p1nk_100k1n_k1nd4_5u5_th0}buckeye{4y000_p1nk_100k1n_k1nd4_5u5_th0}buckeye{4y000_p1nk_100k1n_k1nd4_5u5_th0}buckeye{4y000_p1nk_100k1n_k1nd4_5u5_th0}buckeye{4y000_p1nk_100k1n_k1nd4_5u5_th0}buckeye{4y000_p1nk_100k1n_k1nd4_5u5_th0}buckeye{4y000_p1nk_100k1n_k1nd4_5u5_th0}buckeye{4y000_p1nk_100k1n_k1nd4_5u5_th0}[...]
```

We got the flag!

# Conclusion

What we've learned:

1. Audio Steganography