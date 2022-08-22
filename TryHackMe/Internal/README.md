# Relevant Penetration Testing Report

## Introduction

The Internal penetration testing report contains all efforts that were conducted in order to perform a penetration test on the client's virtual environment network.

## Objective

The objective of this assessment is to perform an internal, external, and web app penetration test against the client's virtual environment network.
I am tasked with following methodical approach in obtaining access to the objective goals. The main objective is to report as many vulnerabilities as the provided virtual environment possible. My goal is to obtain the highest possible privilege level (administrator/root) on the virtual environment.

## Scope of Work

- Ensure that you modify your hosts file to reflect internal.thm
- Any tools or techniques are permitted in this engagement
- Locate and note all vulnerabilities found
- Submit the flags discovered to the dashboard
- Only the IP address assigned to your machine is in scope

# High-Level Summary

I was tasked with performing an internal penetration test towards the virtual environment that the client has provided.
An internal penetration test is a dedicated attack against internally connected systems.
The focus of this test is to perform attacks, similar to those of a hacker and attempt to infiltrate the client's virtual environment.
My overall objective was to evaluate the network, identify systems, and exploit flaws while reporting the findings back to the client.

When performing the internal, external, and web app penetration test, there were several alarming vulnerabilities that were identified on the client's virtual environment.
When performing the attacks, I was able to gain access to the client's provided virtual environment machine, primarily due to outdated patches and poor security configurations.
During the testing, I had administrative level access to the system.
All system was successfully exploited and access granted.
These systems as well as a brief description on how access was obtained are listed below:

- 10.10.241.218 (internal) - Weak password in WordPress which allows attackers to upload, modify a malicious script to the WordPress website. Saved critical file insecurely.

## Recommendations

I recommend patching the vulnerabilities identified during the testing to ensure that an attacker cannot exploit these systems in the future.
One thing to remember is that these systems require frequent patching and once patched, should remain on a regular patch program to protect additional vulnerabilities that are discovered at a later date.

# Methodologies

I utilized a widely adopted approach to performing penetration testing that is effective in testing how well the provided virtual environment are secured.
Below is a breakout of how I was able to identify and exploit the variety of systems and includes all individual vulnerabilities found.

## Information Gathering

The information gathering portion of a penetration test focuses on identifying the scope of the penetration test.
During this penetration test, I was tasked with exploiting the client's provided virtual environment.
The specific IP addresse was: `10.10.241.218`.

## Penetration

The penetration testing portions of the assessment focus heavily on finding all vulnerabilities in the client's provided virtual environment machine.
During this penetration test, I was able to successfully gain complete control on the client's provided virtual environment machine.

### System IP: 10.10.241.218

#### Service Enumeration

The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems.
This is valuable for an attacker as it provides detailed information on potential attack vectors into a system.
Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test.
In some cases, some ports may not be listed.

Server IP Address | Ports Open
------------------|----------------------------------------
10.10.241.218     | **TCP**: 22,80

**Modify my hosts file to reflect `internal.thm`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a1.png)

**Rustscan Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a2.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a3.png)

## HTTP on Port 80

**In web application, I always start with enumerating hidden directory via `gobuster`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a4.png)

Found `/blog/`, `/phpmyadmin/` and `/wordpress/` directory via `gobuster`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a5.png)

In the `/blog/` directory, I found that this web server is using **WordPress** CMS(Content Management System).

***WordPress Enumeration:***

**I will enumerate the WordPress site via `wpscan`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a6.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a7.png)

Found 1 user: `admin`.

**Brute forcing WordPress login page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a8.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a9.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a10.png)

Found user `admin` credentials:

- Username:admin
- Password:my2boys

**Vulnerability Explanation:**

User admin has a weak password that is easily to brute forced by attackers.

**Vulnerability Fix:**

Change a stronger password for the user admin. This could prevent attackers to easily to brute force the admin's password.

**Severity:**

*The calculation is done via CVSS Version 3.1 Calculator(https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator):*

1. **CVSS Base Score: 9.8**
- Impact Subscore: 5.9
- Exploitability Subscore: 3.9
2. **CVSS Temporal Score: 9.6**
- CVSS Environmental Score: 9.6
- Modified Impact Subscore: 5.9
3. **Overall CVSS Score: 9.6**

***Critical***

#### Initial Foothold

Since I have WordPress `admin` credentials, I can now login to `http://internal.thm/blog/wp-login.php` as administrator privilege on WordPress:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a11.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a12.png)

**WordPress reverse shell:**

Since I have administrator privilege on WordPress, I can modify a theme's template to gain an initial foothold on the client's machine:

First, go to "Appearance" -> "Theme Editor", choose one of the templates, then change the PHP content to [PHP reverse shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php):

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a13.png)

Then, setup a `nc` listener and trigger the PHP reverse shell via `curl`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a14.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a15.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a16.png)

**Vulnerability Explanation:**

Since the user `admin`'s password is very weak, this allows attackers to upload, modify a malicious script to the WordPress website.

**Vulnerability Fix:**

Change a stronger password for the user admin. This could prevent attackers to easily to brute force the admin's password.

**Severity:**

*The calculation is done via CVSS Version 3.1 Calculator(https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator):*

1. **CVSS Base Score: 7.2**
- Impact Subscore: 5.9
- Exploitability Subscore: 1.2
2. **CVSS Temporal Score: 7.0**
- CVSS Environmental Score: 7.0
- Modified Impact Subscore: 5.9
3. **Overall CVSS Score: 7.0**

***High***

**Stable Shell:**

Before move to privilege escalation session, I will usually upgrade the reverse shell to fully interactive TTY shell.

To do so, I will use `socat` to achieve this:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a17.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a18.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a19.png)

#### Privilege Escalation

##### www-data to aubreanna

By enumerating the system manaully, I found there is a file that contains MySQL credentials:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a20.png)

**MySQL:**

Found MySQL credentials in `/var/www/html/wordpress/wp-config.php`:

- Username:wordpress
- Password:wordpress123

By enumerating the system manaully, I found there is a file that saves user `aubreanna`'s credentials:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a21.png)

- Username:aubreanna
- Password:bubb13guM!@#123

**We now can Switch User to `aubreanna`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a22.png)

**Vulnerability Explanation:**

Saved critical file insecurely, this could allow attackers to escalate their privilege further.

**Vulnerability Fix:**

Saved critical file securely, such as set it to not world-readable, encrypt it if possible.

**Severity:**

*The calculation is done via CVSS Version 3.1 Calculator(https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator):*

1. **CVSS Base Score: 7.8**
- Impact Subscore: 5.9
- Exploitability Subscore: 1.8
2. **CVSS Temporal Score: 7.6**
- CVSS Environmental Score: 7.6
- Modified Impact Subscore: 5.9
3. **Overall CVSS Score: 7.6**

***High***

**user.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a23.png)

##### aubreanna to root

In the home directory of the user `aubreanna`, there is a file called `jenkins.txt`, and it said `Jenkins` is running on port 8080 in localhost. We can confirm that by issuing command `netstat`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a24.png)

**Local Port Forwarding:**

In order to successfully communicate to the `Jenkins` service, I will use `chisel` to do local port forwarding.

First, transfer the `chisel` binary to the target machine:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a25.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a26.png)

Then, do local port forwarding via `chisel`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a27.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a28.png)

This allows me to communicate to the `Jenkins` service via localhost port 8081 on my attacker machine:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a29.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a30.png)

**Jenkins:**

Now, I will try to brute force the login page via `hydra`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a31.png)

Found `admin` credentials:

- Username:admin
- Password:spongebob

We now can login to `Jenkins` as administrator.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a32.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a33.png)

Since we have `Jenkins` administrator privilege, we can escalate our privilege to root.

To do so, I will:

First, go to "Manage Jenkins":

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a34.png)

Then, click "Script Console":

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a35.png)

Next, Prepare `Groovy` reverse shell from https://www.revshells.com/:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a36.png)

Finally, copy and paste that code to "Script Console", setup a `nc` listener and click "Run":

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a37.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a38.png)

**Vulnerability Explanation:**

User admin has a weak password that is easily to brute forced by attackers.

**Vulnerability Fix:**

Change a stronger password for the user admin. This could prevent attackers to easily to brute force the admin's password. Also, if the attacker has `admin` user's password in `Jenkins`, this could allow attacker to upload, inject a malicious code to the `Jenkins` service, which allows the attacker gain initial shell or privilege escalation.

**Severity:**

*The calculation is done via CVSS Version 3.1 Calculator(https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator):*

1. **CVSS Base Score: 6.7**
- Impact Subscore: 5.9
- Exploitability Subscore: 0.8
2. **CVSS Temporal Score: 6.5**
- CVSS Environmental Score: 6.5
- Modified Impact Subscore: 5.9
3. **Overall CVSS Score: 6.5**

***Medium***

By enumerating manually on the `Jenkins` docker container, I found that there is a file called `note.txt` in `/opt`, which contains `root` credentials.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a39.png)

- Username:root
- Password:tr0ub13guM!@#123

Armed with this information, now I can Switch User to `root` on `internal` machine:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a40.png)

Now I user `root`, which is the highest privilege user in Linux system.

**Vulnerability Explanation:**

Saved critical file insecurely, this could allow attackers to escalate their privilege further.

**Vulnerability Fix:**

Saved critical file securely, such as set it to not world-readable, encrypt it if possible.

**Severity:**

*The calculation is done via CVSS Version 3.1 Calculator(https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator):*

1. **CVSS Base Score: 7.8**
- Impact Subscore: 5.9
- Exploitability Subscore: 1.8
2. **CVSS Temporal Score: 7.6**
- CVSS Environmental Score: 7.6
- Modified Impact Subscore: 5.9
3. **Overall CVSS Score: 7.6**

***High***

**root.txt Contents:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Internal/images/a41.png)

## Maintaining Access

Maintaining access to a system is important to us as attackers, ensuring that we can get back into a system after it has been exploited is invaluable.
The maintaining access phase of the penetration test focuses on ensuring that once the focused attack has occurred (i.e. a remote code execution), we have administrative access over the system again.
Many exploits may only be exploitable once and we may never be able to get back into a system after we have already performed the exploit.

## House Cleaning

The house cleaning portions of the assessment ensures that remnants of the penetration test are removed.
Often fragments of tools or user accounts are left on an organization's computer which can cause security issues down the road.
Ensuring that we are meticulous and no remnants of our penetration test are left over is important.

After collecting trophies from the client's provided virtual environment was completed, I removed all user accounts and passwords as well as all malicious scripts installed on the system.
The client should not have to remove any user accounts or services from the system.