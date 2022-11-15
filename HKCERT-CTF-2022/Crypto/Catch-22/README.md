# Catch-22

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

- Challenge difficulty: ★☆☆☆☆

## Background

You need a key to open the door... but what if the key is in the room?

[http://chal-a.hkcert22.pwnable.hk:28251](http://chal-a.hkcert22.pwnable.hk:28251) , [http://chal-b.hkcert22.pwnable.hk:28251](http://chal-b.hkcert22.pwnable.hk:28251)

Attachment: [catch-22_c445efdb7185cb4c1a7b3002462179d6.zip](https://file.hkcert22.pwnable.hk/catch-22_c445efdb7185cb4c1a7b3002462179d6.zip)

Solution: [https://hackmd.io/@blackb6a/hkcert-ctf-2022-ii-en-6a196795](https://hackmd.io/@blackb6a/hkcert-ctf-2022-ii-en-6a196795)

## Find the flag

**In this challenge, we can download an attachment:**
```
┌──(root🌸siunam)-[~/ctf/HKCERT-CTF-2022/Crypto/Catch-22]
└─# unzip catch-22_c445efdb7185cb4c1a7b3002462179d6.zip           
Archive:  catch-22_c445efdb7185cb4c1a7b3002462179d6.zip
  inflating: package.json            
   creating: src/
  inflating: src/app.js              
   creating: src/views/
  inflating: src/views/home.handlebars  
   creating: src/views/layouts/
  inflating: src/views/layouts/main.handlebars  
  inflating: src/views/register.handlebars  
  inflating: src/util.js             
  inflating: src/actions.js          
  inflating: src/constants.js        
  inflating: yarn.lock
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221112071158.png)

**Let's register an account for testing!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221112071227.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221112071232.png)

**In here, we can see that the map has 2 keys, 1 key is reachable, and has 3 locked door?**

That's impossible to unlock all the door in a normal way!

**Let's look at the source code!**

**util.js:**
```js
const crypto = require('crypto')

const key = crypto.randomBytes(16)

function encryptToken (state) {
  const token = JSON.stringify(state)
  const cipher = crypto.createCipheriv('aes-128-ecb', key, null)
  cipher.setAutoPadding(true)
  const encryptedToken = Buffer.concat([
    cipher.update(token),
    cipher.final()
  ])
  return encryptedToken.toString('hex')
}

function decryptToken (encryptedTokenHex) {
  const encryptedToken = Buffer.from(encryptedTokenHex, 'hex')
  const cipher = crypto.createDecipheriv('aes-128-ecb', key, null)
  cipher.setAutoPadding(true)
  const token = Buffer.concat([
    cipher.update(encryptedToken),
    cipher.final()
  ]).toString()
  const state = JSON.parse(token)
  return { token, state }
}

module.exports = {
  encryptToken,
  decryptToken
}
```

Hmm... We can see **the token is being decrypted and encrypted via AES ECB mode.**

**app.js:**
```js
[...]
app.post('/register', bodyParser.urlencoded(), function (req, res) {
  try {
    const { username } = req.body

    const newToken = encryptToken({
      username,
      x: 13,
      y: 5,
      inventory: [],
      onMapItems: [
        {item: ITEMS.KEY, x: 3, y: 4},
        {item: ITEMS.DOOR, x: 4, y: 5},
        {item: ITEMS.DOOR, x: 5, y: 5},
        {item: ITEMS.DOOR, x: 6, y: 5},
        {item: ITEMS.KEY, x: 15, y: 1},
      ]
    })

    res.cookie('game-token', newToken)
    return res.redirect('/')
  } catch (err) {
    console.error(err)
    return res.status(500).json({ error: 'unexpected error' })
  }
})
[...]
```

**In `app.js`, when we send a POST request in `/register`, it'll assign us a token, and parse it to set a cookie.**

**`decryptToken`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221112072145.png)

```
{"username":"siunam","x":13,"y":5,"inventory":[],"onMapItems":[{"item":0,"x":3,"y":4},{"item":1,"x":4,"y":5},{"item":1,"x":5,"y":5},{"item":1,"x":6,"y":5},{"item":0,"x":15,"y":1}]}
```

**Cookies:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221112072210.png)

```
aca1fae0ede7f469260b38ab325fc0a7c0a578b67ff8e93a7ca255c1802b5178d092ffc0b18edeb060f3fc660a8d84abcf4f7a9b0dccc8ae94e09439f208e9e06ed7d7778ae3d0b1ded2363941565dae601cd81f55858da6fff04a27e13d8f435b7c4b8abbb05ecc99b4679ba42b5538d48ffbe7581c43f177590f71650580b5dfe0cd22903b61749a6b151e921fe4f8e1350780de45150a9fcfb910b4479a4a2c58fc700f9be2af04a501028627908aa6087df656b66d2d2ca83810e594022e
```

**Armed with the above information, we can try to dig much deeper!**

Block ciphers, like AES (Advanced Encryption Standard), are only able to encrypt messages with a fixed length. In our instance, **AES can only encrypt messages of 16 bytes.**

**AES electronic codebook (ECB) mode:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221112072452.png)

In this challenge, we can see in `util.js`, it's using ECB mode, and **each message block is encrypted by every 16 bytes.**

***Let's look at our cookie value!***

**Translate each message block to 16 bytes:**

Plaintext Block  | Ciphertext Block
-----------------|------------------------
{"username":"siu | aca1fae0ede7f469260b38ab325fc0a7
nam","x":13,"y": | c0a578b67ff8e93a7ca255c1802b5178
5,"inventory":[] | d092ffc0b18edeb060f3fc660a8d84ab
,"onMapItems":\[{| cf4f7a9b0dccc8ae94e09439f208e9e0
"item":0,"x":3," | 6ed7d7778ae3d0b1ded2363941565dae
y":4},{"item":1, | 601cd81f55858da6fff04a27e13d8f43
"x":4,"y":5},{"i | 5b7c4b8abbb05ecc99b4679ba42b5538
tem":1,"x":5,"y" | d48ffbe7581c43f177590f71650580b5
:5},{"item":1,"x | dfe0cd22903b61749a6b151e921fe4f8
":6,"y":5},{"ite | e1350780de45150a9fcfb910b4479a4a
m":0,"x":15,"y": | 2c58fc700f9be2af04a501028627908a
1}]}\_\_\_\_\_\_\_\_\_\_\_\_ | a6087df656b66d2d2ca83810e594022e

> Note: 16 bytes = 32 hex characters, `_` = padding character

**Also, since every blocks are independently encrypted, we can just modify one of those block!**

**What if I fill the inventory with bunch of keys by swaping the ciphertext block??**

After I fumbling around, when I pick up a key, the `inventory` will add a value called `0`.

**To swap the ciphertext block, I'll register an account named `siu0,0,0,0,0,0,0,0 0nam`, the ciphertext block will become:**

Plaintext Block  | Ciphertext Block
-----------------|------------------------
{"username":"siu | aca1fae0ede7f469260b38ab325fc0a7
0,0,0,0,0,0,0,0  | 8c1842fb0df889fd6ed5416f7507a0b0
0nam","x":13,"y" | 5762c9742bf323de4593eee85eca5067
:5,"inventory":\[ | f90d10d66852d845107a087525c48918
],"onMapItems":\[ | 42924e9de696556ccd87cd2fc3521bb5
{"item":0,"x":3, | a3b6abc3b51b9451c9830d89b581440c
"y":4},{"item":1 | f7e8419ca8f122e0493ddfc213523685
,"x":4,"y":5},{" | 8922e4617b39d6b06abdbb05c8b1a619
item":1,"x":5,"y | 5656e0d6c9f584984e11a2397e28bdd3
":5},{"item":1," | c19796e2c753f799143f2f5e314ff561
x":6,"y":5},{"it | 90fdf086bfd8d8eb1f8076079eb2d15c
em":0,"x":15,"y" | e3dd02803671e9359bef00fbc4936c1e
:1}]}{padding}   | d38069bc2385c77065fa5fe3781739a1

**You can see that we have a new ciphertext block which filled with bunch of 0's.**

**Now, what if I move the second ciphertext block (0's) to between the fourth and the fifth blocks? If we successfully modify the ciphertext block, it'll be:**
Plaintext Block  | Ciphertext Block
-----------------|------------------------
{"username":"siu | aca1fae0ede7f469260b38ab325fc0a7
0nam","x":13,"y" | 5762c9742bf323de4593eee85eca5067
:5,"inventory":\[ | f90d10d66852d845107a087525c48918
0,0,0,0,0,0,0,0  | 8c1842fb0df889fd6ed5416f7507a0b0
],"onMapItems":\[ | 42924e9de696556ccd87cd2fc3521bb5
{"item":0,"x":3, | a3b6abc3b51b9451c9830d89b581440c
"y":4},{"item":1 | f7e8419ca8f122e0493ddfc213523685
,"x":4,"y":5},{" | 8922e4617b39d6b06abdbb05c8b1a619
item":1,"x":5,"y | 5656e0d6c9f584984e11a2397e28bdd3
":5},{"item":1," | c19796e2c753f799143f2f5e314ff561
x":6,"y":5},{"it | 90fdf086bfd8d8eb1f8076079eb2d15c
em":0,"x":15,"y" | e3dd02803671e9359bef00fbc4936c1e
:1}]}{padding}   | d38069bc2385c77065fa5fe3781739a1

**Which we'll have 8 keys!**

**We can modify the cookie via `document.cookie="game-token=<cookie_value_here>"`.**

**Modified cookie:**
```
document.cookie="game-token=aca1fae0ede7f469260b38ab325fc0a75762c9742bf323de4593eee85eca5067f90d10d66852d845107a087525c489188c1842fb0df889fd6ed5416f7507a0b042924e9de696556ccd87cd2fc3521bb5a3b6abc3b51b9451c9830d89b581440cf7e8419ca8f122e0493ddfc2135236858922e4617b39d6b06abdbb05c8b1a6195656e0d6c9f584984e11a2397e28bdd3c19796e2c753f799143f2f5e314ff56190fdf086bfd8d8eb1f8076079eb2d15ce3dd02803671e9359bef00fbc4936c1ed38069bc2385c77065fa5fe3781739a1"
```

**Let's fire up the developer console and change our cookie!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221112075001.png)

**Now, if we move once, we should see 8 keys in our inventory!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221112075019.png)

**Yes!! Let's unlock all the doors and get the flag!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221112075101.png)

We got the flag!

# Conclusion

What we've learned:

1. Cut-and-Paste Attack in AES ECB Mode