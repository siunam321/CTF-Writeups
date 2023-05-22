# CrashPython

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Find the flag](#find-the-flag)
4. [Conclusion](#conclusion)

## Overview

- 145 solves / 50 points
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

I am hosting an uncrashable Python executor API. Crash it to get the flag.

- Junhua

[http://34.124.157.94:5000](http://34.124.157.94:5000)

## Find the flag

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/images/Pasted%20image%2020230520203921.png)

In here, this web application is an online Python interpreter, which runs Python code.

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/Misc/CrashPython/dist.zip):**
```shell
┌[siunam♥earth]-(~/ctf/Grey-Cat-The-Flag-2023-Qualifiers/Misc/CrashPython)-[2023.05.20|20:42:32(HKT)]
└> file dist.zip 
dist.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥earth]-(~/ctf/Grey-Cat-The-Flag-2023-Qualifiers/Misc/CrashPython)-[2023.05.20|20:42:34(HKT)]
└> unzip dist.zip 
Archive:  dist.zip
   creating: nginx/
  inflating: nginx/dockerfile        
  inflating: nginx/nginx.conf        
  inflating: nginx/project.conf      
  inflating: docker-compose.yml      
  inflating: judge0.conf             
   creating: app/
  inflating: app/app.py              
  inflating: app/constants.py        
  inflating: app/dockerfile          
 extracting: app/requirements.txt    
   creating: app/templates/
  inflating: app/templates/base.html  
  inflating: app/templates/index.html  
  inflating: app/templates/results.html  
  inflating: app/wsgi.py             
```

**Let's look at `docker-compose.yml` first:**
```yaml
version: '3.7'

x-logging:
  &default-logging
  logging:
    driver: json-file
    options:
      max-size: 100M

services:
  flask_app:
    container_name: flask_app
    restart: always
    build: ./app
    command: gunicorn -w 1 -b 0.0.0.0:8000 wsgi:app

  nginx:
    container_name: nginx
    restart: always
    build: ./nginx
    ports:
      - "5000:80"
    depends_on:
      - flask_app

  server:
    image: judge0/judge0:latest
    volumes:
      - ./judge0.conf:/judge0.conf:ro
    ports:
      - "2358:2358"
    privileged: true
    <<: *default-logging
    restart: always

  worker:
    image: judge0/judge0:latest
    command: [ "./scripts/workers" ]
    volumes:
      - ./judge0.conf:/judge0.conf:ro
    privileged: true
    <<: *default-logging
    restart: always

  db:
    image: postgres:13.0
    env_file: judge0.conf
    volumes:
      - postgres-data:/var/lib/postgresql/data/
    <<: *default-logging
    restart: always

  redis:
    image: redis:6.0
    command:
      [
        "bash",
        "-c",
        'docker-entrypoint.sh --appendonly yes --requirepass "$$REDIS_PASSWORD"'
      ]
    env_file: judge0.conf
    volumes:
      - redis-data:/data
    <<: *default-logging
    restart: always

volumes:
  postgres-data:
  redis-data:
```

As you can see, there're 2 interesting services: `flask_app`, `worker`.

**In `flask_app` service's `/app/app.py`, route `/` in the main logic of the web application:**
```python
@app.route('/', methods=['GET', 'POST'])
def index() -> Response:
    """The main endpoint"""
    if request.method == 'GET':
        with open(__file__) as f:
            source_code = f.read()
        return render_template('index.html', banned_words=BANNED_WORDS, source_code=source_code)
    args = request.form
    code = args.get('code', '')

    if len(code) == 0:
        flash('Code cannot be empty', ERROR)
        return redirect('/')

    # Sanitize code
    code = sanitize(code)
    if len(code) == 0:
        return redirect('/')

    # Send to judge0
    token = send_code_to_execute(code)
    if len(token) == 0:
        flash('An unexpected error occurred', ERROR)
        return redirect('/')

    flash("Sucessfully sent", SUCCESS)
    return redirect(f"/view/{token}")
```

**When the `code` GET parameter is not empty, it'll first run function `sanitize()`:**
```python
def sanitize(code: str) -> str:
    """Sanitize code"""
    for word in BANNED_WORDS:
        if word in code:
            flash(f'Banned word detected: "{word}"', ERROR)
            return ''
    return code
```

**`/app/constants.py`:**
```python
[...]
BANNED_WORDS = [
    'os',
    'eval',
    'exec',
    'subprocess',
    'threading',
    'multiprocessing',
    'raise',
    'quit',
    'sys',
    'stdout',
    'stderr',
    'x',
]
```

Basically it's checking any `BANNED_WORDS` in our `code`'s value.

**After sanitized, it'll call function `send_code_to_execute()`:**
```python
    # Send to judge0
    token = send_code_to_execute(code)
[...]
def send_code_to_execute(code: str) -> str:
    """Send code to judge0 to execute"""
    b64_code = b64encode(code.encode()).decode()
    with requests.Session() as s:
        resp = s.post(JUDGE0_SUBMIT_URL, data={
            'source_code': b64_code,
            'language_id': 71,  # Python3
            'stdin': '',
        })
    return resp.json().get('token', '')
```

> Judge0 is a robust, scalable, and [open-source](https://github.com/judge0/judge0) online code execution system that can be used to build a wide range of applications that need online code execution features. Some examples include competitive programming platforms, e-learning platforms, candidate assessment and recruitment platforms, online code editors, online IDEs, and many more. (From [https://judge0.com/](https://judge0.com/))

**Then, in route `/view/<path:path>`, we see this:**
```python
@app.route('/view/<path:path>', methods=['GET'])
def view_code(path: str) -> Response:
    """View the submitted code"""
    view_url = f'{JUDGE0_BASE_URL}/submissions/{path}/?base64_encoded=true'
    with requests.Session() as session:
        resp = session.get(view_url)
        data = resp.json()

    for key in DECODE_KEYS:
        if data.get(key, False):
            data[key] = b64decode(data[key]).decode()

    status = data.get('status', {}).get('id', 0)
    message = data.get('message', '')
    stderr = data.get('stderr', '')

    if status == 11 and message == "Exited with error status 139" and 'Segmentation fault' in stderr:
        flash(f"Congrats, you got the flag: {FLAG}!", SUCCESS)
    return render_template('results.html', **data)
```

With that said, this challenge's aim is NOT about gaining Remote Code Execution (RCE), as **the `worker` service (Judge0) is an isolated Docker container.** Even if we gain RCE, we can't read the flag.

**So, our goal is to crash the Python programe with segmentation fault (segfault).**

**However, instead of Googling "How to crash a Python programe with segmentation fault", I wanna try to use LLM (Large Language Model) like ChatGPT:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/images/Pasted%20image%2020230520205546.png)

**Let's give it a shot!**
```python
import ctypes
ctypes.string_at(0)
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/images/Pasted%20image%2020230520205603.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/images/Pasted%20image%2020230520205608.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/images/Pasted%20image%2020230520205625.png)

Lmao, it worked!

- **Flag: `grey{pyth0n-cv3-2021-3177_0r_n0t?_cd924ee8df15912dd55c718685517d24}`**

> Fun fact: CVE-2021-3177 is Python 3.x through 3.9.1 has a buffer overflow in `PyCArg_repr` in `_ctypes/callproc.c`, which may lead to remote code execution in certain Python applications that accept floating-point numbers as untrusted input, as demonstrated by a `1e300` argument to `c_double.from_param`. This occurs because sprintf is used unsafely. (From [https://nvd.nist.gov/vuln/detail/CVE-2021-3177](https://nvd.nist.gov/vuln/detail/CVE-2021-3177))

## Conclusion

What we've learned:

1. Crashing Python With Segmentation Fault Via `ctypes` Library