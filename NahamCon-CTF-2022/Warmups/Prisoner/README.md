# Background
![background](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Warmups/Prisoner/images/background.png)

![question](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Warmups/Prisoner/images/question.png)

In this challenge, you have to exit the python script. At that time I was asking myself, if I'm inside a python editor, how do I exit? So I pressed `Ctrl+D` to exit that script.

![question](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Warmups/Prisoner/images/question1.png)

And yes! I've successfully escape that python script!

Next, since the flag is in ./flag.txt, so I was googling `How to cat a file inside the python editor`, and I found this:
```
import os

os.system("command")
```

![question](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Warmups/Prisoner/images/flag.png)

Finally!! We've the flag, let's submit it.