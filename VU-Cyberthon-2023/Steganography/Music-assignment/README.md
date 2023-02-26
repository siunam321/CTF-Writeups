# Music assignment

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225161252.png)

## Find the flag

**In this challenge, we can download a file:**
```shell
┌[siunam♥earth]-(~/ctf/VU-Cyberthon-2023/Steganography/Music-assignment)-[2023.02.25|18:58:17(HKT)]
└> file Music_assignment.zip 
Music_assignment.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥earth]-(~/ctf/VU-Cyberthon-2023/Steganography/Music-assignment)-[2023.02.25|18:58:18(HKT)]
└> unzip Music_assignment.zip 
Archive:  Music_assignment.zip
  inflating: VU Cyberthon 2023.html
```

**We can open it in `firefox`:**
```shell
┌[siunam♥earth]-(~/ctf/VU-Cyberthon-2023/Steganography/Music-assignment)-[2023.02.25|18:58:21(HKT)]
└> firefox VU\ Cyberthon\ 2023.html
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225185849.png)

Hmm... Nothing weird?

**Let's view the source page:**
```html
<meta property=og:description content="The aim of the VU Cyberthon is to inspire and encourage participants for independent analysis of cyber security problems and security methods, to develop critical thinking and creativity while solving challenges.">
<meta property=og:image content=https://www.cyberthon.lt/img/share.png>
<meta property=og:image content=https://bit.ly/simple-png>
[...]
```

**The `bit.ly` link looks sussy:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225185937.png)

It's a google drive shared file!

**Let's download it!**
```shell
┌[siunam♥earth]-(~/ctf/VU-Cyberthon-2023/Steganography/Music-assignment)-[2023.02.25|18:58:32(HKT)]
└> file CT-Instrument-23.wav 
CT-Instrument-23.wav: RIFF (little-endian) data, WAVE audio, Microsoft PCM, 8 bit, mono 11050 Hz
```

It's a WAV sound file.

**If we open it in Audacity and listen it, you'll find that it's a morse code:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225190046.png)

**We can go to [an online tool](https://morsecode.world/international/decoder/audio-decoder-adaptive.html) to decode it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225190223.png)

We found it!

- **Flag: `VU{CYBERTHON2023}`**

# Conclusion

What we've learned:

1. Decoding Morse Code In An Audio File