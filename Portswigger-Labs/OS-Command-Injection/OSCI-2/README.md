# Blind OS command injection with time delays

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays), you'll learn: Blind OS command injection with time delays! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a blind [OS command injection](https://portswigger.net/web-security/os-command-injection) vulnerability in the feedback function.

The application executes a shell command containing the user-supplied details. The output from the command is not returned in the response.

To solve the lab, exploit the blind OS [command injection](https://portswigger.net/web-security/os-command-injection) vulnerability to cause a 10 second delay.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-2/images/Pasted%20image%2020221222225710.png)

**Feedback page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-2/images/Pasted%20image%2020221222225723.png)

**Let's try to submit a feedback, and intercept the request via Burp Suite:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-2/images/Pasted%20image%2020221222225849.png)

When we clicked the `Submit feedback` button, **it'll send a POST request to `/feedback/submit`, with parameter `csrf`, `name`, `email`, `subject`, and `message`.**

Let's test for OS command injection!

The `email`, `subject` and `message` parameters seems interesting, it might be parsed to a shell command call `mail`.

**If in that case, we can try to injection a payload:**
```sh
|| ping -c 10 127.0.0.1%0a
```

In here, we **pipe(parse) the previous command into `ping`**, which will ping localhost 10 times. Also, **we'll need to provide a newline character(`\n` or `%0a` in URL encoding)**, to execute the `ping` command.

Let's try it!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-2/images/Pasted%20image%2020221222231254.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-2/images/Pasted%20image%2020221222231307.png)

It indeed waited for 10 seconds!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-2/images/Pasted%20image%2020221222231353.png)

# What we've learned:

1. Blind OS command injection with time delays