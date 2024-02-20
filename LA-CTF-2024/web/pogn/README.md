# pogn

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @colonneil
- Contributor: @obeidat.
- 188 solves / 388 points
- Author: r2uwu2
- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

Pogn in mong.

[pogn.chall.lac.tf](https://pogn.chall.lac.tf)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219140001.png)

## Enumeration

**Index page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219140150.png)

In here, we can play a game called "Pong".

`lactf{7_supp0s3_y0u_g0t_b3773r_NaNaNaN}`

When we lost the game, it pops up an alert box:

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219140223.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219140341.png)

As you can see, this web application communicates with the server using WebSocket (ws).

**Burp Suite WebSockets history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219140446.png)

Hmm... Not sure what those data for.

Not much we can do in here, let's dig through this web application's source code.

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/web/pogn/pogn.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/LA-CTF-2024/web/pogn)-[2024.02.19|14:05:53(HKT)]
└> file pogn.zip              
pogn.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥Mercury]-(~/ctf/LA-CTF-2024/web/pogn)-[2024.02.19|14:05:54(HKT)]
└> unzip pogn.zip              
Archive:  pogn.zip
  inflating: Dockerfile              
  inflating: package.json            
  inflating: package-lock.json       
   creating: src/
  inflating: src/index.html          
  inflating: src/style.css           
  inflating: src/pogn.js             
  inflating: src/server.js
```

By reading the source code, we have the following findings:

**`src/server.js`:**
```javascript
[...]
app.ws('/ws', (ws, req) => {
  [...]
  const Msg = {
    GAME_UPDATE: 0,
    CLIENT_UPDATE: 1,
    GAME_END: 2
  };
     [...]
      // check if there has been a winner
      // server wins
      if (ball[0] < 0) {
        ws.send(JSON.stringify([
          Msg.GAME_END,
          'oh no you have lost, have you considered getting better'
        ]));
        clearInterval(interval);

      // game still happening
      } else if (ball[0] < 100) {
        ws.send(JSON.stringify([
          Msg.GAME_UPDATE,
          [ball, me]
        ]));

      // user wins
      } else {
        ws.send(JSON.stringify([
          Msg.GAME_END,
          'omg u won, i guess you considered getting better ' +
          'here is a flag: ' + flag,
          [ball, me]
        ]));
[...]
```

When we **win the game**, the server will **return a message with the flag**.

How to win the game? Well, it's when **the game's ball X position (`ball[0]`) is greater than `100`**.

Hmm... Can we modify the server's ball/paddle?

**In the `message` event on the server-side, it looks like this:**
```javascript
[...]
  ws.on('message', (data) => {
    try {
      const msg = JSON.parse(data);
      if (msg[0] === Msg.CLIENT_UPDATE) {
        const [ paddle, paddleV ] = msg[1];
        if (!isNumArray(paddle) || !isNumArray(paddleV)) return;
        op = [clamp(paddle[0], 0, 50), paddle[1]];
        opV = mul(normalize(paddleV), 2);
      }
    } catch (e) {}
  });
[...]
```

As you can see, when a new WebSocket message with `CLIENT_UPDATE` (`1`) message is received on the server-side, it'll update our user's paddle X Y position and paddle vector.

So... Nope, we can't modify the server's ball/paddle.

How about the client-side?

**`src/pogn.js`:**
```javascript
[...]
const clamp = (x, low, high) => min(max(x, low), high);
[...]
const viewportToServer = ([x, y]) => [
  x * 100 / innerWidth,
  y * 30 / (0.5 * innerHeight) - 30
];
[...]
ws.addEventListener('open', () => {
  ws.addEventListener('message', (e) => {
    const msg = JSON.parse(e.data);
    switch (msg[0]) {
      case Msg.GAME_UPDATE:
        ballPos = serverToViewport(msg[1][0]);
        serverPos = serverToViewport(msg[1][1]);
        updateFromRemote();
        break;
      case Msg.GAME_END:
        alert(msg[1]);
        break;
    }
  })

  const interval = setInterval(() => {
    if (!moved) return;
    ws.send(JSON.stringify([
      Msg.CLIENT_UPDATE,
      [ userPos, v ]
    ]));
  }, 50);

  ws.addEventListener('close', () => clearInterval(interval));
});

const $ = x => document.querySelector(x);

const userPaddle = $('.user.paddle');
const serverPaddle I got tired of people leaking my password from the db so I moved it out of the db. [penguin.chall.lac.tf](https://penguin.chall.lac.tf)= $('.server.paddle');
const ball = $('.ball');

let moved = false;
let p_x = 0;
let p_y = 0;
let v = [0, 0];
window.addEventListener('mousemove', (e) => {
  moved = true;
  const x = clamp(e.clientX, 0, innerWidth / 2 - 48);
  const y = e.clientY;
  userPaddle.style = `--x: ${x}px; --y: ${y}px`;
  userPos = viewportToServer([ x, y ]);
  v = viewportToServer([0.01 * (x - p_x), 0.01 * (y - p_y)]);
  p_x = x;
  p_y = y;
});
[...]
```

In here, when our mouse has moved, it'll send our user's X Y position and vector to the server.

## Exploitation

Hmm... I wonder what will happen when our user's X Y position and vector are `0`? If our paddle stays in the Y middle axis, and vector X Y are 0, the game ball should just flies to the other end when it collides with us.

**To do so, we can use our browser console to patch the client-side JavaScript code:**
```javascript
userPos = [0, 0];
v = [0, 0];
moved = true;
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219154443.png)

Nice! Here's the flag!

- **Flag: `lactf{7_supp0s3_y0u_g0t_b3773r_NaNaNaN}`**

## Conclusion

What we've learned:

1. Exploiting WebSocket