# Re:Zero

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- 210 solves / 150 points
- Author: GonJK
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113164156.png)

1. Complete Achievement 0 - 20
2. No Revives, No Kill, Dealt 0 damage in game

Once completed, refresh the browser and the flag will be printed on the console.

Web: [http://chal.hkcert23.pwnable.hk:28040](http://chal.hkcert23.pwnable.hk:28040)

**Note:** There is a guide for this challenge [here](https://hackmd.io/@blackb6a/hkcert-ctf-2023-i-en-a58d115f39feab46).

## Enumeration

In this challenge, we can go to a web application:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113175934.png)

In here, we can play a multiplayer game called "BrowserQuest".

> BrowserQuest is a tribute to classic video-games with a multiplayer twist. You play as a young warrior driven by the thrill of adventure. No princess to save here, just a dangerous world filled with treasures to discover. And it’s all done in glorious HTML5 and JavaScript. (from [https://hacks.mozilla.org/2012/03/browserquest/](https://hacks.mozilla.org/2012/03/browserquest/))

Without further ado, let's dive into the game!

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113180315.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113180338.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113180456.png)

After clicked the "PLAY" button, we'll can play with the game and start our adventure!

In this challenge's description, it said:

1. Complete Achievement 0 - 20
2. No Revives, No Kill, Dealt 0 damage in game

Once completed, refresh the browser and the flag will be printed on the console.

Wait... How can I finish all ***21 (0 - 20)*** achievements with no revives, no kill, and dealt 0 damage in the game...

When we clicked the "PLAY" button, it popped up a "How to play" popup, and it mentioned **our character is automatically saved as we play**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113180857.png)

Hmm... I wonder how our session/game data is being saved... Cookies? Local storage?

**We can use the development tools to find that out:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113181154.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113181216.png)

**Now, we can go to the "Storage" tab ("Application" tab in Chrome) and view stored cookies and local storage:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113181320.png)

Nothing in cookies...

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113181337.png)

Ah ha! We found it! It's in local storage!

**In our local storage, there's a key called `data`, with the following value:**
```json
{"hasAlreadyPlayed":true,"player":{"name":"siunam","weapon":"sword1","armor":"clotharmor","image":"data:image/png;base64,iVBORw0[...]ggg=="},"achievements":{"unlocked":[],"ratCount":0,"skeletonCount":0,"totalKills":0,"totalDmg":0,"totalRevives":0}}
```

**Beautified:**
```json
{
    "hasAlreadyPlayed": true,
    "player":
    {
        "name": "siunam",
        "weapon": "sword1",
        "armor": "clotharmor",
        "image": "data:image/png;base64,iVBORw0[...]ggg=="
    },
    "achievements":
    {
        "unlocked":
        [],
        "ratCount": 0,
        "skeletonCount": 0,
        "totalKills": 0,
        "totalDmg": 0,
        "totalRevives": 0
    }
}
```

As you can see, our achievements are currently empty.

Hmm... Looks like the game doesn't check the integrity of our game data! Which means we should be able to modify it to whatever we want!

## Exploitation

But before we do that, we need to know the format of the achievements.

**So let's try to talk to an NPC and get a sample:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113181944.png)

**Then, view the local storage `data` key's value again:**
```json
{
    "hasAlreadyPlayed": true,
    "player":
    {
        "name": "siunam",
        "weapon": "sword1",
        "armor": "clotharmor",
        "image": "data:image/png;base64,iVBORw0[...]ggg=="
    },
    "achievements":
    {
        "unlocked":
        [
            4
        ],
        "ratCount": 0,
        "skeletonCount": 0,
        "totalKills": 0,
        "totalDmg": 0,
        "totalRevives": 0
    }
}
```

Now we know the format of the achievements!

**Let's modify that!**
```json
{
    "hasAlreadyPlayed": true,
    "player":
    {
        "name": "siunam",
        "weapon": "sword1",
        "armor": "clotharmor",
        "image": "data:image/png;base64,iVBORw0[...]ggg=="
    },
    "achievements":
    {
        "unlocked":
        [
            0,
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            9,
            10,
            11,
            12,
            13,
            14,
            15,
            16,
            17,
            18,
            19,
            20
        ],
        "ratCount": 0,
        "skeletonCount": 0,
        "totalKills": 0,
        "totalDmg": 0,
        "totalRevives": 0
    }
}
```

**Finally, copy and paste the above modified JSON data, and refresh the page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113182347.png)

We got the flag!

- **Flag: `hkcert23{m0dm0d__loc4l__stor4g3}`**

## Conclusion

What we've learned:

1. Modifying local storage data