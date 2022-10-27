# Horror Feeds

## Background

> An unknown entity has taken over every screen worldwide and is broadcasting this haunted feed that introduces paranormal activity to random internet-accessible CCTV devices. Could you take down this streaming service?

> Difficulty: Easy

- Overall difficulty for me: Very hard

**In this challenge, you can spawn a docker instance and [download a file](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Horror-Feeds/web_horror_feeds.zip):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Horror-Feeds/images/a1.png)

```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Web/Horror-Feeds]
└─# unzip web_horror_feeds.zip 
Archive:  web_horror_feeds.zip
   creating: web_horror_feeds/
  inflating: web_horror_feeds/entrypoint.sh  
   creating: web_horror_feeds/challenge/
  inflating: web_horror_feeds/challenge/run.py  
   creating: web_horror_feeds/challenge/application/
  inflating: web_horror_feeds/challenge/application/database.py  
   creating: web_horror_feeds/challenge/application/static/
   creating: web_horror_feeds/challenge/application/static/images/
  inflating: web_horror_feeds/challenge/application/static/images/logo.png  
  inflating: web_horror_feeds/challenge/application/static/images/test.png 
[...]
```

## Find the flag

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Horror-Feeds/images/a2.png)

In the home page, **we can login and register a user.**

**In the `dashboard.html`template, we need to login as `admin` to get the flag:**
```html
            {% if user == 'admin' %}
            <div class="container-lg mt-5 pt-5">
                <h5 class="m-3 ms-0">Firmware Settings</h5>
                <h6 class="m-4 ms-0 text-grey">Upgrade Firmware</h6>
                [...]
                <td>5</td>
                <td>192.251.68.6</td>
                <td>NV360</td>
                <td>{{flag}}</td>
                <td></td>
                <td></td>
                <td>admin</td>
                <td>80</td>
                <td>21</td>
                <td>23</td>
                <td></td>
                [...]
```

**Also, in the `config.py`, we can see a MySQL credentials:**
```py
class Config(object):
    SECRET_KEY = generate(50)
    MYSQL_HOST = 'localhost'
    MYSQL_USER = 'user'
    MYSQL_PASSWORD = 'M@k3l@R!d3s$'
    MYSQL_DB = 'horror_feeds'
    FLAG = open('/flag.txt').read()
```

However, when I try to login, I received a 500 status, and the response is JSON ValueError.

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Horror-Feeds/images/a3.png)

What if I enter an invalid user?

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Horror-Feeds/images/a4.png)

Status 403, and outputs `Invalid credentials`!

**In the `routes.py`, we can see how the login is being implemented:**
```py
@api.route('/login', methods=['POST'])
def api_login():
    if not request.is_json:
        return response('Invalid JSON!'), 400
    
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    if not username or not password:
        return response('All fields are required!'), 401
    
    user = login(username, password)
    
    if user:
        session['auth'] = user
        return response('Success'), 200
        
    return response('Invalid credentials!'), 403
```

**`database.py`:**
```py
def login(username, password):
    user = query_db('SELECT password FROM users WHERE username = %s', (username,), one=True)

    if user:
        password_check = verify_hash(password, user.get('password'))

        if password_check:
            token = generate_token(username)
            return token
        else:
            return False
    else:
        return False
```

**Function `verify_hash` and `generate_token` from `util.py`:**
```py
def generate_token(username):
    token_expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=360)
    
    encoded = jwt.encode(
        {
            'username': username,
            'exp': token_expiration
        },
        key,
        algorithm='HS256'
    )

    return encoded

def verify_hash(password, passhash):
    return bcrypt.checkpw(password.encode(), passhash.encode())
```

**What the `login` function is:**
- If the username is correct, then do a password check in bcrypt
- If the password check is correct, it'll generate a JWT (JSON Web Token) token

**Hmm... What if I register an new account?**

**`routes.py`:**
```py
@api.route('/register', methods=['POST'])
def api_register():
    if not request.is_json:
        return response('Invalid JSON!'), 400
    
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
        
    if not username or not password:
        return response('All fields are required!'), 400
    
    user = register(username, password)
    
    if user:
        return response('User registered! Please login')
    
    return response('User exists already!'), 409
```

**`database.py`:**
```py
def register(username, password):
    exists = query_db('SELECT * FROM users WHERE username = %s', (username,))
   
    if exists:
        return False
    
    hashed = generate_password_hash(password)

    query_db(f'INSERT INTO users (username, password) VALUES ("{username}", "{hashed}")')
    mysql.connection.commit()

    return True
```

**`util.py`:**
```py
def generate_password_hash(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()
```

- If the username is not exist, it'll generate a bcrypt hash and stored the username and hashed password to the database

**How about after we're authenticated?**

**`routes.py`:**
```py
@web.route('/dashboard')
@is_authenticated
def dashboard():
    current_user = token_verify(session.get('auth'))
    return render_template('dashboard.html', flag=current_app.config['FLAG'], user=current_user.get('username'))
```

**`util.py`:**
```py
def token_verify(token):
    try:
        token_decode = jwt.decode(
            token,
            key,
            algorithms='HS256'
        )

        return token_decode
    except:
        return abort(400, 'Invalid token!')

def is_authenticated(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = session.get('auth')

        if not token:
            return abort(401, 'Unauthorised access detected!')

        token_verify(token)

        return f(*args, **kwargs)

    return decorator
```

- If JWT `token` is set, it'll verify our token by decoding it 
- If the JWT token is set and verified, we'll be redirected to `/dashboard`

**Now, armed with the above information, we can try to register an account, and play around with the JWK token.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Horror-Feeds/images/a5.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Horror-Feeds/images/a6.png)

**Let's look at the JWT token in cookie!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Horror-Feeds/images/a7.png)

```
eyJhdXRoIjoiZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SjFjMlZ5Ym1GdFpTSTZJbk5wZFc1aGJTSXNJbVY0Y0NJNk1UWTJOalk0TlRFd05YMC5jU0NqQThtV19BRVJWRHZpMm5VSmczZkFEN2R4aS1CeXl4QW1CZU43c0NjIn0.Y1dEUQ.ksQNdZ4FLdScVeDxGfNvVrpk_QE
```

**Let's look at `util.py` how the application generate a JWT token!**
```py
def generate_token(username):
    token_expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=360)
    
    encoded = jwt.encode(
        {
            'username': username,
            'exp': token_expiration
        },
        key,
        algorithm='HS256'
    )

    return encoded
```

**The JWT token contains:**
- `username`, which is our account username
- `exp`, which is the current UTC time, + 6 hours

```py
print(datetime.timedelta(minutes=360))
6:00:00

print(datetime.datetime.utcnow())
2022-10-25 02:19:40.847664

print(datetime.datetime.utcnow() + datetime.timedelta(minutes=360))
2022-10-25 08:19:57.859686
```

- `key`, which is a 50 characters long of random hex string
- The JWT algorith is `HS256`

**Hmm... What if we change the JWT token to the admin's token?**

**Now, we can go to [https://jwt.io/](https://jwt.io/) try to decode that token:**

`Invalid Signature`?

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Horror-Feeds/images/a8.png)

Looks like it's a nested JWT token!

**Let's decode it again:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Horror-Feeds/images/a9.png)

It works!

**What if I change the `username` to `admin`, then encode it again?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Horror-Feeds/images/a10.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Horror-Feeds/images/a11.png)

**Now, let's change the `session` cookie to our newly generated JWT token:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Horror-Feeds/images/a12.png)

Hmm... `Unauthorised access detected!`.

Then I stuck at here and have no clue what to do next...