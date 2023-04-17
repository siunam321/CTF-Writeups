# Terrific Trigonometry Tutor

## TTT

### Overview

- 69 Points / 99 Solves

- Overall difficulty for me (From 1-10 stars): ★★★★★★★★★★

### Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230416144757.png)

### Enumeration

In this challenge, there's a web application:

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230416144833.png)

Which allows you to do some trigonometry calculations.

**We can also view the source code:**
```shell
┌[siunam♥earth]-(~/ctf/PlaidCTF-2023/misc/Terrific-Trigonometry-Tutor/TTT)-[2023.04.16|14:49:08(HKT)]
└> file ttt.0317e9c2446d934d03676d0d506d7a77bbef1f2b7f500556cd29c2af16caae8d.tar    
tttt.0317e9c2446d934d03676d0d506d7a77bbef1f2b7f500556cd29c2af16caae8d.tar: POSIX tar archive
┌[siunam♥earth]-(~/ctf/PlaidCTF-2023/misc/Terrific-Trigonometry-Tutor/TTT)-[2023.04.16|14:49:14(HKT)]
└> tar -xf ttt.0317e9c2446d934d03676d0d506d7a77bbef1f2b7f500556cd29c2af16caae8d.tar
┌[siunam♥earth]-(~/ctf/PlaidCTF-2023/misc/Terrific-Trigonometry-Tutor/TTT)-[2023.04.16|14:49:19(HKT)]
└> ls -lah chal  
total 24K
drwxr-xr-x 4 siunam nam 4.0K Apr 15 17:55 .
drwxr-xr-x 3 siunam nam 4.0K Apr 16 14:37 ..
-rw-r--r-- 1 siunam nam  463 Apr 15 04:16 Dockerfile
drwxr-xr-x 3 siunam nam 4.0K Apr 15 04:05 static
drwxr-xr-x 2 siunam nam 4.0K Apr 15 04:05 templates
-rw-r--r-- 1 siunam nam 2.2K Apr 16 14:42 trig.py
```

**trig.py:**
```py
from flask import Flask, url_for, render_template, request
from ast import literal_eval
import sympy

app = Flask(__name__)

@app.route("/")
def index():
    return render_template('index.html')


regular_operators = {
    'add': lambda x, y: x + y,
    'sub': lambda x, y: x - y,
    'mul': lambda x, y: x * y,
    'div': lambda x, y: x / y,
    'pow': lambda x, y: x ** y,
}

trig_operators = {
    'sin': sympy.sin,
    'cos': sympy.cos,
    'tan': sympy.tan,
    'cot': sympy.cot,
    'sec': sympy.sec,
    'csc': sympy.csc,
    'asin': sympy.asin,
    'acos': sympy.acos,
    'atan': sympy.atan,
    'acot': sympy.acot,
    'asec': sympy.asec,
    'acsc': sympy.acsc,
}


def postfix_calculator(inp):
    stack = []
    for (ty, val) in inp:
        if ty == 'num':
            stack.append(literal_eval(val))
        elif ty == 'var':
            stack.append(sympy.Symbol(val))
        elif ty == 'op':
            if val in regular_operators:
                a = stack.pop()
                b = stack.pop()
                stack.append(regular_operators[val](b, a))
            elif val in trig_operators:
                a = stack.pop()
                stack.append(trig_operators[val](a))
            else:
                raise ValueError("Invalid operator")
    return stack


@app.post("/compute")
def compute():
    try:
        expr = postfix_calculator(request.get_json())
        if len(expr) == 1:
            return sympy.latex(expr[0]) + r'\\=\\' + sympy.latex(sympy.simplify(expr[0]))
        else:
            return r'\quad{}'.join(map(sympy.latex, expr)) + r'\\=\\\cdots'
    except Exception as e:
        return "invalid expression"
```

In this Flask web application, there's a POST route called `/compute`.

This route needs a JSON data, and perform some trigonometry calculations.

**Right off the bat, I saw this:**
```py
if ty == 'num':
    stack.append(literal_eval(val))
```

`literal_eval`??

**After some Googling, I found this [StackOverflow post](https://stackoverflow.com/questions/15197673/using-pythons-eval-vs-ast-literal-eval):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230416145220.png)

Hmm... Seems no luck to gain RCE (Remote Code Execution), just like normal `eval`.

**However, I decided to ask ChatGPT to bypass `literal_eval`:**

```
Prompt: Can you give an example of how to bypass the security measures of literal_eval?

Answer: While it is difficult to craft input that can bypass the security measures of literal_eval, there have been vulnerabilities in the past that allowed for code execution via literal_eval. One such example is the "pickle deserialization" vulnerability, which affects Python versions before 3.8.3.

In this vulnerability, an attacker can craft a malicious pickle object that, when deserialized using literal_eval, executes arbitrary code on the system. Here's an example:

import pickle

class Exploit:
    def __reduce__(self):
        import os
        return (os.system, ("echo 'exploited'",))

exploit = pickle.dumps(Exploit())

# This input executes the code in the pickle object
output = eval(pickle.loads(exploit))
In this example, we define a class Exploit that defines the __reduce__ method. This method is called when the object is pickled, and it returns a tuple that specifies the function to call and its arguments. In this case, we're returning the os.system function with the argument "echo 'exploited'", which will execute the echo command when literal_eval is called on the deserialized object.

When we pickle the Exploit object and pass it to literal_eval, the __reduce__ method is called and the os.system function is executed, which runs the echo command and outputs the message "exploited".

It's worth noting that this vulnerability has been patched in Python 3.8.3 and later versions, so it's important to keep your Python installation up-to-date to prevent these types of attacks. Additionally, it's important to sanitize and validate any input that is passed to literal_eval, or to use a safer alternative if possible.
```

Wait, it's vulnerable to pickle deserialization??

Let's build the pickle payload!

```py
#!/usr/bin/env python3
import pickle

def main():
    class Exploit:
        def __reduce__(self):
            import os
            return (os.system, ("cat flag",))

    exploit = pickle.dumps(Exploit())
    print(f'[*] Payload: {exploit}')

if __name__ == '__main__':
    main()
```

```py
┌[siunam♥earth]-(~/ctf/PlaidCTF-2023/misc/Terrific-Trigonometry-Tutor/TTT)-[2023.04.16|14:49:25(HKT)]
└> python3 test.py 
[*] Payload: b'\x80\x04\x95#\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x94\x8c\x06system\x94\x93\x94\x8c\x08cat flag\x94\x85\x94R\x94.'
```

**Then, do local testing for that payload:**
```py
[...]
if ty == 'num':
    stack.append(literal_eval(val))
    literal_eval("__import__('pickle').loads(b'\x80\x04\x95#\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x94\x8c\x06system\x94\x93\x94\x8c\x08cat flag\x94\x85\x94R\x94.')")
[...]
if __name__ == '__main__':
    app.run(debug=True)
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230416145616.png)

```shell
┌[siunam♥earth]-(~/ctf/PlaidCTF-2023/misc/Terrific-Trigonometry-Tutor/TTT)-[2023.04.16|14:38:25(HKT)]
└> python3 chal/trig.py
[...]
1
127.0.0.1 - - [16/Apr/2023 14:56:05] "POST /compute HTTP/1.1" 200 -
```

Nope.

However, I tried to find other vulnerabilities like LaTeX injection, but still no luck...