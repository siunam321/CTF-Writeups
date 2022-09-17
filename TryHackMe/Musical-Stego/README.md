# Musical Stego

## Introduction

Welcome to my another writeup! In this TryHackMe [Musical Stego](https://tryhackme.com/room/musicalstego) room, there are tons of stuff that's worth learning! Without further ado, let's dive in.

## Background

> This audio file is hiding some things, are you able to extract enough data to reveal the flag?

> Difficulty: Medium

```
Download and listen to the audio file. Can you complete this challenge?

Struggling? Complete the CCStego room first.
```

- Overall difficulty for me: Very easy

# Download the file

You can download the file at [Musical Stego](https://tryhackme.com/room/musicalstego) room on TryHackMe. 

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Musical_Stego]
└─# file 'Language Arts DEF CON 27 The Official Soundtrack .wav' 
Language Arts DEF CON 27 The Official Soundtrack .wav: RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, stereo 44100 Hz
```

# Who remixed the song?

**We can use `exiftool` to view metadata of this `wav` file:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Musical_Stego]
└─# exiftool info Language\ Arts\ DEF\ CON\ 27\ The\ Official\ Soundtrack\ .wav 
[...]
Title                           : Luckiness (Kilmanjaro Remix)
[...]
```

# What link is hiding in the music?

We can use `audacity` to view **spectrogram** of an audio file:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Musical-Stego/images/a1.png)

Found a QR code.

By scanning that QR code, it takes me to https://vocaroo.com/imPgJC013AW:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Musical-Stego/images/a2.png)

And it's hiding a link: https://voca.ro/imPgJC013AW, which is an `mp3` audio file.

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Musical_Stego]
└─# file Vocaroo\ imPgJC013AW.mp3                               
Vocaroo imPgJC013AW.mp3: Audio file with ID3 version 2.4.0, contains:\012- MPEG ADTS, layer III,  v2.5,  24 kbps, 8 kHz, Monaural
```

# What does the found audio convert to? [CHECK HINT, LINK IS DEAD]

By listening the `mp3` audio file, I can recongize it's morse code.

**We can upload this `mp3` file to [morse decoder](https://morsecode.world/international/decoder/audio-decoder-adaptive.html):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Musical-Stego/images/a3.png)

`https://pastebin.com/lzktb4et`

> Hint: https://github.com/m00-git/XXXXXXXX Replace the last 8 characters of the github link with the last 8 characters of the pastebin link found in the audio. Sorry about the less than ideal solution, "Paste will never expire" just doesn't mean what it used to I guess.

# What was the found password?

> Note: However, the pastebin link AND the github link are dead, so I have to look at some walkthroughs to complete this.

`S3CR3T_P455`

# What is the final flag?

Since we got 2 files, maybe they hide something inside?

**We can use `steghide` to extract hidden file with the password:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Musical_Stego]
└─# steghide extract -sf Language\ Arts\ DEF\ CON\ 27\ The\ Official\ Soundtrack\ .wav 
Enter passphrase: 
wrote extracted data to "secret".

┌──(root🌸siunam)-[~/ctf/thm/ctf/Musical_Stego]
└─# file secret                         
secret: ASCII text

┌──(root🌸siunam)-[~/ctf/thm/ctf/Musical_Stego]
└─# cat secret          
THM{Redacted}
```

# Conclusion

What we've learned:

1. Audio Steganography
2. Spectrogram
3. Morse Code Decoder
4. Extract Hidden Stuff In a File via `steghide`