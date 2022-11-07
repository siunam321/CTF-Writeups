# pong

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

> I dug up my first ever JavaScript game, but this time, my AI is unbeatable!! Hah!

[https://pong.chall.pwnoh.io](https://pong.chall.pwnoh.io)

> Author: gsemaj

> Difficulty: Beginner

## Find the flag

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221104225452.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221104225519.png)

In here, we can play the classic ping-pong game.

**Since JavaScript is a client-side language, we can use our console in the developer tool to control some variables.**

Let's view the source page!

```js
<script src="/socket.io/socket.io.js"></script>
        <script>
            const socket = io();
            const canvas = document.getElementById("game");
            const pl = .16;
            const pw = .02;
            const bs = .04;
            var up = 0;
            var down = 0;
            var p1 = .5;
            var p2 = .5;
            var bx = .5;
            var by = .5;
            var bvx = 0;
            var bvy = 0;
            var spin = 0;
            var bt = 0;
            var s1 = 0;
            var s2 = 0;
            function reset(ctx) {
                ctx.resetTransform();
                ctx.translate(0, 0.5);
                ctx.lineWidth = 1;
            }
            function set() {
                bx = 0.5;
                by = 0.5;
                bvx = 0;
                bvy = 0;
                bt = 0;
                spin = 0;
            }
            function draw() {
                canvas.width = canvas.clientWidth;
                canvas.height = canvas.clientHeight;
                const w = canvas.width;
                const h = canvas.height;
                const ctx = canvas.getContext("2d");
                reset(ctx);
                ctx.fillStyle = "#FFFFFF";
                ctx.fillRect(0, 0, w, h);
                // field lines
                ctx.fillStyle = "#aaaaaa";
                for(var y = 0; y < 1; y += .1) {
                    ctx.fillRect(w / 2 - 5, (y + .025) * h, 10, .05 * h);
                }
                // ball
                ctx.fillStyle = "#000000";
                ctx.translate(bx * w, by * h);
                bt += spin;
                while(bt < 0) bt += 360;
                while(bt > 359) bt -= 360;
                ctx.rotate(bt * Math.PI / 180);
                
                ctx.fillRect(-(bs * h) / 2, -(bs * h) / 2, bs * h, bs * h);
                reset(ctx);
                // paddles
                ctx.fillStyle = "#000000";
                ctx.fillRect(pw * w, (p1 - pl / 2) * h, pw * w, pl * h);
                ctx.fillRect((1 - 2 * pw) * w, (p2 - pl / 2) * h, pw * w, pl * h);
                // scores
                for(var x = 0; x < 20; x++) {
                    ctx.beginPath();
                    ctx.rect(x * .05 * w, 0, .05 * w, 0.01 * h);
                    ctx.stroke();
                    if(x < s1) ctx.fillRect(x * .05 * w, 0, .05 * w, 0.01 * h);
                    if(x > 9 && s2 > 19 - x) ctx.fillRect(x * .05 * w, 0, .05 * w, 0.01 * h);
                }
            }
            function tick() {
                const w = canvas.width;
                const h = canvas.height;
                // controls
                if(p1 - up * .01 > pl / 2) p1 -= up * .01;
                if(p1 + down * .01 < 1 - pl / 2) p1 += down * .01;
                p2 = by;
                // ball
                if(bvx != 0) spin = bvy / bvx * 5;
                bx += bvx;
                by += bvy;
                if(by < 0 || by > 1) bvy *= -1; // v bounce
                if(bx < pw * 2) {
                    // left paddle bounce
                    if(by > p1 - pl / 2 && by < p1 + pl / 2) {
                        let diff = by - p1;
                        bvy = .015 * diff / (pl / 2);
                        bvx = .015 - Math.abs(bvy);
                    }
                }
                if(bx > 1 - pw * 2) {
                    // right paddle bounce
                    if(by > p2 - pl / 2 && by < p2 + pl / 2) {
                        let diff = by - p2;
                        bvy = .015 * diff / (pl / 2);
                        bvx = -(.015 - Math.abs(bvy));
                    }   
                }
                if(bx < -.1 || bx > 1.1) {
                    socket.emit("score", bx);
                }
                draw();
            }
            function init() {
                draw();
                setInterval(tick, 13);
                document.addEventListener("keydown", (e) => {
                    if(e.key == "w") up = 1;
                    if(e.key == "s") down = 1;
                    if(e.key == "p") {
                        socket.emit("begin");
                    }
                });
                document.addEventListener("keyup", (e) => {
                    if(e.key == "w") up = 0;
                    if(e.key == "s") down = 0;
                });
            }
            socket.on("alert", (msg) => alert(msg));
            socket.on("begin", (params) => {
                bvx = params.bvx;
                bvy = params.bvy;
            });
            socket.on("set", (scores) => {
                set();
                s1 = scores.sx1;
                s2 = scores.sx2;
            });
        </script>
```

**Let's break it down:**
- If we press `W` key, our character moves up
- If we press `S` key, our character moves down
- If we press `P` key, it'll start the game

**After fumbling around, I found that I can control our score:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221104225914.png)

`s1` is our score, `s2` is the opponent score.

But that's not helpful to get the flag... **Our objective should be winning 1 round of the game.**

**Again, after I pooking around, I found that we can control the ball!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221104230121.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221104230138.png)

**Hmm... What if I set the `bx` value is greater than 1?? Will the ball just goes through the opponent??**

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221104230246.png)

Oh! We got the flag!

# Conclusion

What we've learned:

1. Abusing JavaScript Variables