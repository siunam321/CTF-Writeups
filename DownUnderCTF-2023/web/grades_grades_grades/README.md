# grades_grades_grades

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @siunam
- 363 solves / 100 points
- Author: donfran
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Sign up and see those grades :D! How well did you do this year's subject? Author: donfran

[https://web-grades-grades-grades-c4627b227382.2023.ductf.dev](https://web-grades-grades-grades-c4627b227382.2023.ductf.dev)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230903205717.png)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230903210048.png)

Hmm... Looks like we can sign up a new account:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230903210117.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230903210140.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230903210240.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230903210916.png)

After logged in, we can check our assignment grades in `/grades` route:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230903210317.png)

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/web/grades_grades_grades/grades_grades_grades.tar.gz):**
```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2023/web/grades_grades_grades)-[2023.09.03|21:04:04(HKT)]
└> file grades_grades_grades.tar.gz 
grades_grades_grades.tar.gz: gzip compressed data, from Unix, original size modulo 2^32 30720
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2023/web/grades_grades_grades)-[2023.09.03|21:04:05(HKT)]
└> tar xf grades_grades_grades.tar.gz 
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2023/web/grades_grades_grades)-[2023.09.03|21:04:07(HKT)]
└> ls -lah grades_grades_grades
total 32K
drwxr-xr-x 3 siunam nam 4.0K Aug 24 10:36 .
drwxr-xr-x 3 siunam nam 4.0K Sep  3 21:04 ..
-rw-r--r-- 1 siunam nam  357 Aug 24 10:36 Dockerfile
-rw-r--r-- 1 siunam nam  175 Aug 22 21:20 Pipfile
-rwxr-xr-x 1 siunam nam   26 Aug 24 10:36 requirements.txt
-rwxr-xr-x 1 siunam nam  116 Aug 24 10:36 run.py
-rwxr-xr-x 1 siunam nam   79 Aug 24 10:36 run.sh
drwxr-xr-x 3 siunam nam 4.0K Aug 24 10:44 src
```

After digging through the source code, we can view the main logic of the web application in `src/auth.py` and `src/routes.py`.

**In `src/routes.py`, we can see there's a `/grades_flag`, which will response us with the flag's content:**
```python
@api.route('/grades_flag', methods=('GET',))
@requires_teacher
def flag():
    return render_template('flag.html', flag="FAKE{real_flag_is_on_the_server}", is_auth=True, is_teacher_role=True)
```

However, **it requires teacher role**.

**Decorator `requires_teacher` in `src/auth.py`:**
```python
SECRET_KEY = secrets.token_hex(32)
[...]
def decode_token(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return None
[...]
def requires_teacher(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('auth_token')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            data = decode_token(token)
            if data is None or data.get("is_teacher") is None:
                return jsonify({'message': 'Invalid token'}), 401
            if data['is_teacher']:
                request.user_data = data
            else:
                return jsonify({'message': 'Invalid token'}), 401
        except jwt.DecodeError:
            return jsonify({'message': 'Invalid token'}), 401

        return f(*args, **kwargs)

    return decorated
```

In here, it's verifying our JWT from the cookie, and **it's checking the JWT has `is_teacher` claim.**

## Exploitation

Hmm... How can we sign arbitrary JWT... We can't crack the secert key because of random 32 bytes.

**After fumbling around, I found that the `/signup` route is very interesting:**
```python
@api.route('/signup', methods=('POST', 'GET'))
def signup():

    # make sure user isn't authenticated
    if is_teacher_role():
        return render_template('public.html', is_auth=True, is_teacher_role=True)
    elif is_authenticated():
        return render_template('public.html', is_auth=True)

    # get form data
    if request.method == 'POST':
        jwt_data = request.form.to_dict()
        jwt_cookie = current_app.auth.create_token(jwt_data)
        if is_teacher_role():
            response = make_response(redirect(url_for('api.index', is_auth=True, is_teacher_role=True)))
        else:
            response = make_response(redirect(url_for('api.index', is_auth=True)))
        
        response.set_cookie('auth_token', jwt_cookie, httponly=True)
        return response

    return render_template('signup.html')
```

**When POST request is being sent, it'll convert the request data to data type dictionary, and call function `create_token()` from `src/auth.py`:**
```python
def create_token(data):
    token = jwt.encode(data, SECRET_KEY, algorithm='HS256')
    return token
```

This function will sign the JWT with the given POST data.

**Ah ha! What if I provide the `is_teacher` POST parameter? Will it sign the JWT as normal??**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230903212121.png)

**Decoded JWT:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230903212155.png)

Nice!! Our `is_teacher` payload claim is there!

**Let's get the flag with that JWT!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230903212311.png)

- **Flag: `DUCTF{Y0u_Kn0W_M4Ss_A5s1GnM3Nt_c890ne89c3}`**

## Conclusion

What we've learned:

1. Sign arbitrary JWT via flawed signing process