# GlasgowSmile

## Background

> Come for the smiles, stay for the jokes. 

- Author: [Alessandro 'mindsflee' Salzano](https://www.vulnhub.com/entry/glasgow-smile-11,491/)

- Released on: Sep 01, 2020

- Difficulty: Hard

- Overall difficulty for me: Medium
	- Initial foothold: Medium
	- Privilege Escalation: Easy

> In this machine, I'm not using Offensive Security's Proving Grounds Play to interact with this machine, as I have some trouble the VPN. Hence, I downloaded the virtual machine image and imported to my VMWare Workstation.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a0.png)

# Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a1.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a2.png)

According to `rustscan` result, we have 2 ports are opened:

Ports Open        | Service
------------------|------------------------
22                | OpenSSH 7.9p1 Debian
80                | Apache httpd 2.4.38

## HTTP on Port 80

Always enumerate HTTP first, as it has the largest attack vectors.

**Gobuster Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a3.png)

Found `/joomla/` directory, and `how_to.txt` file.

**how_to.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a4.png)

Nothing useful.

**`/joomla/`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a5.png)

This looks like the `joomla` CMS(Content Management System).

**We can also see that there is a `robots.txt` crawler file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a6.png)

Maybe we can brute force `/administrator/` login page later:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a7.png)

Since this is a `joomla` CMS, we can use `joomscan` to enumerate this CMS. (Just like WordPress's `wpscan`.)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a8.png)

**Joomscan Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a9.png)

Found `joomla` version: 3.7.3rc1

**Searchsploit Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a10.png)

XSS is not gonna help.

Okay, take a step back. Since we saw there are 2 login forms, we can try to create a custom wordlist, and brute force it:

**Custom Wordlist:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a11.png)

**Brute Forcing Login Forms:**

> I tried to use `hydra` to brute force, but failed. Maybe the request is too complex.

**Burp Suite:**

Let's brute force the `/joomla/index.php` login form first:

- Intercept the POST request:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a12.png)

- Send to "Intruder": (Ctrl+i)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a13.png)

- In the "Payloads", paste the wordlist's text to "Payload Options":

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a14.png)

- Clear all attack position, only add the "password" field, and "Start Attack":

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a15.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a16.png)

Found a credentials! (You can see the "Length" is different from others.)

- Username:joomla
- Password:Gotham

# Initial Foothold

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a17.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a18.png)

We're able to login to the login from in the `/joomla/index.php`.

How about `/joomla/administrator`?

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a19.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a20.png)

Yes we can!

**Once we're logged in, we can modify a PHP template into PHP reverse shell. (Like WordPress modifying a theme template.)**

To do so, we can:

- Go to "Extensions" -> "Templates" -> "Templates":

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a21.png)

- Choose one of those templates:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a22.png)

- Modify `index.php` to a [PHP reverse shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php), then click "Save":

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a23.png)

- Setup a `nc` listener and trigger the PHP reverse shell by clicking the "Template Preview" button:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a24.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a25.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a26.png)

I'm `www-data`!

**Stable Shell via `socat`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a27.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a28.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a29.png)

# Privilege Escalation

## www-data to rob

Just like Initial foothold in WordPress, after getting a reverse shell, make sure to check `configuration.php`, as it always contains some credtentials.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a30.png)

- MySQL Username:joomla
- MySQL Password:babyjoker

**MySQL Enumeration:**

There is 1 database that is unusual:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a31.png)

**batjoke Database:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a32.png)

Looks like we found bunch of credentials!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a33.png)

Username        | Password
----------------|------------------------
bane            | baneishere
aaron           | aaronishere
carnage         | carnageishere
buster          | busterishereff
rob             | ???AllIHaveAreNegativeThoughts???
aunt            | auntis the fuck here

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a34.png)

There are 3 users in the target machine: `abner`, `penguin` and `rob`.

Let's **Switch User** to `rob` first, as he has the most unique password:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a35.png)

And I'm `rob`!

**user.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a36.png)

## rob to abner

In `rob`'s home directory, there are 2 files that are very odd:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a37.png)

The `Abnerineedyourhelp` looks like a strings that is being rotated. Let's use [CyberChef](https://gchq.github.io/CyberChef/) to rotate the text: (I learned this from Cicada 3301 and other CTF challeneges.)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a38.png)

It's been rotated for once, and we can see there is a base64 string which is `abner`'s password! Let's decode that:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a39.png)

- Username:abner
- Password:I33hope99my0death000makes44more8cents00than0my0life0

Let's **Switch User** to `abner`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a40.png)

I'm `abner`!

**user2.txt**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a41.png)

## abner to penguin

In `abner`'s home directory, the `.bash_history` revealed something:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a42.png)

The `dear_penguins` seems interesting. Let's `find` where is it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a43.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a44.png)

Ahh... It needs a password. Let's transfer this `zip` file to my attacker machine, and crack it via `john`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a45.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a46.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a47.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a48.png)

Hmm... Maybe **password reuse**?? As the file owner is `abner`.

- ZIP Password:I33hope99my0death000makes44more8cents00than0my0life0

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a49.png)

Unziped! Maybe this is the reason why `john` wouldn't crack it, as it's uncrackable.

**dear_penguins:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a50.png)

Maybe it's a password for `penguin`??

- Username:penguins
- Password:scf4W7q4B4caTMRhSFYmktMsn87F35UkmKttM5Bz

Let's **Switch User** to `penguin` again!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a51.png)

**user3.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a52.png)

## penguin to root

In `penguin` home's `SomeoneWhoHidesBehindAMask` directory, there are 3 things are important:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a53.png)

Joker said because of a permissions issue he can't make it work.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a54.png)

The `find` SUID sticky bit seems like a rabbit hole, as the owner of the file is `penguin`, which we can't escalate to root.

However, we could escalate to root via the `.trash_old` Bash script if a cronjob running this script as root. Since we are `penguin` user, thus we have write access to that file.

**pspy:**

Then, I decided to find cronjob processes via [`pspy`](https://github.com/DominicBreuker/pspy), and I was able to find **a cronjob is running as root every minute**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a55.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a56.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a57.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a58.png)

Since we have write access to `.trash_old` Bash script, we can finally escalate to root!! Let's modify the Bash script to add SUID sticky bit to `/bin/bash`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a59.png)

Now, let's wait for the cronjob runs, it'll add SUID sticky bit to `/bin/bash`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a60.png)

The cronjob runs and indeed added SUID sticky bit to `/bin/bash`! We now can spawn a bash shell with SUID privilege.

And we're root! :D

# Rooted

**root.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/GlasgowSmile/images/a61.png)

# Conclusion

What we've learned:

1. Directory Enumeration
2. Joomla Enumeration
3. Brute Forcing Login Form via Burp Suite
4. Joomla Reverse Shell
5. Privilege Escalation via Finding Credentials in MySQL Databases
6. Privilege Escalation via Rotating Text and Found Credentials (`Caesar Cipher`)
7. Privilege Escalation via Password Reuse in a Password Protected ZIP File
8. Privilege Escalation via Misconfigured Bash Script File Permission