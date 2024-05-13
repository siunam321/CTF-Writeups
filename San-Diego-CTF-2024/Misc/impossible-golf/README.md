# impossible-golf

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Find the Flag](#find-the-flag)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @siunam
- 86 solves / 125 points
- Difficulty: Easy
- Author: Infernis
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

I found this golf game online but the third level is so hard 😩😩

See if you can beat it!

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513143615.png)

## Enumeration

In this challenge, we can connect to the challenge instance via WebSocket proxy:

```shell
┌[siunam♥Mercury]-(~/ctf/San-Diego-CTF-2024/Misc/impossible-golf)-[2024.05.13|14:36:40(HKT)]
└> wsrx connect wss://ctf.sdc.tf/api/proxy/c0120805-0c18-4383-ba42-045c18afa378
2024-05-13T06:37:10.730609Z  INFO wsrx::cli::connect: Hi, I am not RX, RX is here -> 127.0.0.1:43677
2024-05-13T06:37:10.730651Z  WARN wsrx::cli::connect: wsrx will not report non-critical errors by default, you can set `RUST_LOG=wsrx=debug` to see more details.
```

**Index page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513143950.png)

In here, we can play a golf web game!

**By viewing the source page (Ctrl + U), we can see that there's a JavaScript file being loaded:**
```html
[...]
<script type="text/javascript" src="golf.js"></script>
[...]
```

Let's read those JavaScript code!

**`/golf.js`:**
```javascript
[...]
const ws = new WebSocket(window.location.href.replace(/^http/, "ws").replace(/\/$/, "").replace(/^https/, "wss"));
[...]
document.addEventListener("mouseup", e => {
    mousedown = false;
    mouse.x2 = e.x;
    mouse.y2 = e.y;
    if (ws.readyState === ws.OPEN) {
        ws.send(JSON.stringify({
            type: "launch",
            value: {
                dx: (mouse.x1 - mouse.x2) / SLOWNESS,
                dy: (mouse.y1 - mouse.y2) / SLOWNESS
            }
        }));
    }
});
[...]
```

As you can see, the web game uses **[WebSocket](https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API)** to communicate with the server!

When our mouse is pressed and released, it'll send a WebSocket message with type `launch` to the server, which launches our ball to the direction that we want.

**Below is the actions when the server reply back to our WebSocket client:**
```javascript
[...]
ws.addEventListener("message", msg => {
    let data;
    try {
        data = JSON.parse(msg.data);
    } catch(e) {}
    switch(data.type) {
        case "colliders":
            colliders = data.value;
        break;
        case "ball":
            ball = {
                ...data.value,
                r: 12
            };
        break;
        case "flag":
            flag = data.value;
        break;
        case "congrats":
            document.body.innerHTML = `Thank you so much a for to playing my game! ` + data.value;
        case "start":
            draw();
        break;
    }
});
[...]
```

In here, it has some interesting WebSocket message type, such as `flag`, `congrats`.

Hmm... Now I wonder how the server process our WebSocket messages.

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/Misc/impossible-golf/server.js):**
```shell
┌[siunam♥Mercury]-(~/ctf/San-Diego-CTF-2024/Misc/impossible-golf)-[2024.05.13|14:41:28(HKT)]
└> file server.js
server.js: JavaScript source, ASCII text, with CRLF line terminators
```

After reviewing the server's code, we can learn the following details:

**When we completed the final level, the server sends WebSocket message type `congrats`, which includes the flag:**
```javascript
[...]
if (goalTimer > 50) {
    level++;
    if (level >= levels.length) {
        ws.send(JSON.stringify({
            type: "congrats",
            value: process.env.GZCTF_FLAG
        }));
        ws.close();
        return;
    }
    goalTimer = 0;
    gameState = JSON.parse(JSON.stringify(levels[level]));
    init();
}
[...]
let levels = [{
    goal: { x: 230, y: 420, r: 20 },
    circle: { x: 200, y: 200, dx: 0, dy: 0, r: 12 },
    rects: [
        [150, 500, 1000, WALL_THICKNESS],
        [150, 300, WALL_THICKNESS, 230],
        [150, 300, 800, WALL_THICKNESS],
        [1150, 50, WALL_THICKNESS, 480],
        [150, 50, 1000, WALL_THICKNESS],
        [150, 50, WALL_THICKNESS, 280],
        [400, 50, WALL_THICKNESS, 180],
        [600, 150, WALL_THICKNESS, 150],
        [800, 50, WALL_THICKNESS, 180],
        [500, 400, 450, WALL_THICKNESS]
    ]
},{
  [...]
```

**There're 3 levels in this game:**
```shell
┌[siunam♥Mercury]-(~/ctf/San-Diego-CTF-2024/Misc/impossible-golf)-[2024.05.13|14:59:48(HKT)]
└> nodejs
[...]
> const WALL_THICKNESS = 30;
undefined
> let levels = [{
...     goal: { x: 230, y: 420, r: 20 },
...     [...]
> levels.length
3
```

**But most importantly, the server implement a built-in cheating mechanism!!** 
```javascript
[...]
ws.on("message", data => {
    let parsed;
    try {
        parsed = JSON.parse(data.toString?.());
    } catch (e) {}
    if (!parsed) return;
    
    switch (parsed?.type) {
        case "launch":
            if (!parsed?.value) return;
            if (typeof parsed?.value?.dx !== "number") return;
            if (typeof parsed?.value?.dy !== "number") return;
            launchBall(gameState.circle, parsed.value);
        break;
        case "cheat":
            gameState.circle.x = gameState.goal.x;
            gameState.circle.y = gameState.goal.y;
        break;
    }
});
[...]
```

When the server received **WebSocket message type `cheat`**, **it'll set our ball (`circle`) X and Y position to the goal X and Y position!!**

That being said, when we send the message type `cheat`, we'll automatically win the current level!

## Find the Flag

Armed with the above information, we can get the flag by just **sending WebSocket message type `cheat` 3 times**!

**To do so, we can use our browser console:**
```javascript
setInterval(() => {
    ws.send(JSON.stringify({type: "cheat"}));
}, 1000);
```

This JavaScript code will send WebSocket message type `cheat` every 1 second.

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513151409.png)

Nice! We got the flag!

- **Flag: `sdctf{i'm in your walls 5762a7bb-1a13-426e-81f4-d1785e1a872f}`**

## Conclusion

What we've learned:

1. WebSocket