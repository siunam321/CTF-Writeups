# Chandi Bot

## Table of Contents

1. **[Chandi Bot 1](#chandi-bot-1)**
2. **[Chandi Bot 2](#chandi-bot-2)**
3. **[Chandi Bot 3](#chandi-bot-3)**
4. **[Chandi Bot 4](#chandi-bot-4)**
5. **[Chandi Bot 5](#chandi-bot-5)**
6. **[Chandi Bot 6](#chandi-bot-6)**

## Chandi Bot 1

- 66 Points / 290 Solves

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆☆

## Background

Have you noticed the funny bot on the server?

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401163838.png)

## Find the flag

**In the RITSEC CTF Discord server, we can see there's a bot:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401163914.png)

**And the it's profile is hiding something!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401164126.png)

- **Flag: `RS{QUANTUM_RESISTANT_ENCRYPTION}`**

## Chandi Bot 2

- 69 Points / 278 Solves

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆☆

## Background

Looks like the bot has some functionality.

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401164206.png)

## Find the flag

Discord bot can be interacted with some commands.

**Sometimes you can view commands via `/`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401164355.png)

**Let's use the `/flag` command!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401164415.png)

- **Flag: `RS{HMMM_WHAT_ARE_YOU_LOOKING_AT}`**

## Chandi Bot 3

- 294 Points / 73 Solves

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆☆

## Background

I wonder what the bot's favorite dinosaur is?

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402162635.png)

## Find the flag

If we send a message that contains "dinosaur", it'll reply us with some random dinosaur names:

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402162739.png)

However, I think that just a rabbit hole.

Then, I start to think: "Any command that's interesting?"

**Yes we do. Like the `/stego` command:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402162855.png)

**Hmm... Let's upload a random PNG image file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402162921.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402162929.png)

Let's download it!

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402162948.png)

```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Chandi-Bot)-[2023.04.02|16:30:05(HKT)]
└> wget https://media.discordapp.net/ephemeral-attachments/1091391452866682950/1092001499086864384/encoded.png
```

**According to [HackTricks](https://book.hacktricks.xyz/crypto-and-stego/stego-tricks#zsteg), we can use a tool called [`zsteg`](https://github.com/zed-0xff/zsteg) to run all the checks:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402163216.png)

```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Chandi-Bot)-[2023.04.02|16:30:08(HKT)]
└> zsteg -a encoded.png
b8,b,msb,xy         .. file: RDI Acoustic Doppler Current Profiler (ADCP)
b8,rgb,msb,xy       .. file: RDI Acoustic Doppler Current Profiler (ADCP)
b8,bgr,msb,xy       .. file: RDI Acoustic Doppler Current Profiler (ADCP)
b1,rgb,lsb,yx       .. text: "RS{GO_GET_THE_ENCODED_FLAG}"
[...]
```

Boom! We found the flag!

- **Flag: `RS{GO_GET_THE_ENCODED_FLAG}`**

## Chandi Bot 4

- 183 Points / 147 Solves

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆☆

## Background

Can you beat the bot?

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401225337.png)

## Find the flag

In this challenge, we need 3 commands: ***`/balance` to check how many point we have, `/rps` to play "Rock Paper Scissors" to gain points, `/dad` to gain 1 point, `/buy-flag` to buy flag for 10000 points***

**First, let's check our balance:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401225541.png)

We got 0 point.

**Then, gain 1 point by using `/dad` command:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401225613.png)

**Next, use `/rps` to play "Rock Paper Scissors":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401225700.png)

Hmm... we can't wager 0 points...

I wonder can we go negative points:

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401225747.png)

Ohh!! We can! And we gain 1 point!!

**Let's use that logic vulnerbility to gain 9999999 points!!**
```
/rps choice:Rock wager:-9999999
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401225855.png)

Boom! We have 10000001 points!!

**Finally, we can use `/buy-flag` command to buy the flag!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401230008.png)

- **Flag: `RS{TWO_NEGATIVES_DO_MAKE_A_POSITIVE}`**

## Chandi Bot 5

- 83 Points / 207 Solves

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆☆

## Background

How much do you know about RITSEC?

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401165213.png)

## Find the flag

**After some testing, I found there's a command called `/trivia`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401165245.png)

**Command:**
```
/trivia RITSEC Trivia
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401165312.png)

After we entered that command, it'll prompt us some questions.

### Q: Who is the current President of RITSEC?

**We can go to their [website](https://www.ritsec.club/about.html) and found the current President:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401165438.png)

- Answer: `Bradley Harker`

### Q: When was RITSEC founded?

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401165508.png)

**In their [Twitter account](https://twitter.com/ritsecclub), we can see that it's "Joined August 2018":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401165658.png)

- Answer: `2018`

### Q: What year was the first version of ChandiBot featured in the RITSEC CTF?

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401165718.png)

Maybe 2022? I couldn't find any information about that, perhaps I'm weak in OSINT.

- Answer: `2022`

### Q: What was the original name of the RITSEC CTF?

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401170226.png)

**By looking through previous RITSEC CTF in [CTFtime](https://ctftime.org/ctf/170/), it's called RC3 CTF:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401170305.png)

- Answer: `RC3 CTF`

### Q: When was Sparsa founded? 

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401170335.png)

**In the [RITSEC about page](https://www.ritsec.club/about.html), it's founded in 2002:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401170432.png)

- Answer: `2002`

### Q: What is RITSEC's main website?

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401170605.png)

**RITSEC main website is at `ritsec.club`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401170624.png)

- Answer: `ritsec.club`

### Q: When was the first RITSEC CTF? 

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401170701.png)

Let's go to [CTFtime](https://ctftime.org/ctf/170)!

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401170739.png)

- Answer: `2018`

### Q: When was the first ISTS

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401170802.png)

**After some Googling, I found the 12th annual of ISTS:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401171252.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401171301.png)

**The 12th annual of ISTS is in 2015, so $$ 2015 - 12 = 2002 $$ year:**

- Answer: `2002`

### Q: When was RC3 founded?

**In [RITSEC about page](https://www.ritsec.club/about.html), it's founded at 2013:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401171708.png)

- Answer: `2013`

### Q: What is the name of the RITSEC Current Discord Bot?

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401171855.png)

If we join to [RITSEC Discord server](https://discord.com/invite/W7NefdyzHZ), it'll have a bot called "OBI"

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401172020.png)

- Answer: `OBII`

### Q: What is the name of RITSEC's CTF Team?

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401172145.png)

**In [CTFtime](https://ctftime.org/event/1860/), we see their team name:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401172230.png)

- Answer: `Contagion`

### Q: Who was the first President of RITSEC? 

**Go to the [RITSEC about page](https://www.ritsec.club/about.html):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401172347.png)

- Answer: `Micah Martin`

## Flag

After answering all 10 questions, we can get the flag:

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401172501.png)

- **Flag: `RS{TRIVIAL_TRIVIA_TRIUMPHS}`**

## Chandi Bot 6

- 190 Points / 117 Solves

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆☆

## Background

We finally found the source code. Can you dig through find the secret?

`https://github.com/1nv8rzim/Chandi-Bot`

## Find the flag

**In this challenge, it gives us a [GitHub repository of the bot](https://github.com/1nv8rzim/Chandi-Bot)'s link:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402160903.png)

Right off the bat, we see there are **14 commits** in branch "master", and **3 branches**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402161006.png)

**Let's clone that repository!**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Chandi-Bot)-[2023.04.02|16:08:23(HKT)]
└> git clone https://github.com/1nv8rzim/Chandi-Bot.git
Cloning into 'Chandi-Bot'...
[...]
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Chandi-Bot)-[2023.04.02|16:10:35(HKT)]
└> cd Chandi-Bot/; ls -lah
total 96K
drwxr-xr-x 8 siunam nam 4.0K Apr  2 16:10 .
drwxr-xr-x 3 siunam nam 4.0K Apr  2 16:10 ..
drwxr-xr-x 2 siunam nam 4.0K Apr  2 16:10 bot
drwxr-xr-x 5 siunam nam 4.0K Apr  2 16:10 commands
drwxr-xr-x 2 siunam nam 4.0K Apr  2 16:10 config
-rw-r--r-- 1 siunam nam   31 Apr  2 16:10 config_example.yml
drwxr-xr-x 8 siunam nam 4.0K Apr  2 16:10 .git
-rw-r--r-- 1 siunam nam   22 Apr  2 16:10 .gitignore
-rw-r--r-- 1 siunam nam  916 Apr  2 16:10 go.mod
-rw-r--r-- 1 siunam nam  47K Apr  2 16:10 go.sum
drwxr-xr-x 2 siunam nam 4.0K Apr  2 16:10 helpers
-rw-r--r-- 1 siunam nam  498 Apr  2 16:10 main.go
drwxr-xr-x 2 siunam nam 4.0K Apr  2 16:10 structs
```

Now, sometimes a version control's repository could contain some ***sensitive information in commits***, like API key, private SSH key, credentials, and other stuff like the flag.

**To view commits in Git, we can use:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Chandi-Bot/Chandi-Bot)-[2023.04.02|16:10:41(HKT)]-[git://master ✔]
└> git log -p
commit 91520f529945a5846c54feb28f7645437ce820b2 (HEAD -> master, origin/master, origin/HEAD)
Author: Maxwell Fusco <54746239+1nv8rzim@users.noreply.github.com>
[...]
diff --git a/commands/enabled.go b/commands/enabled.go
new file mode 100644
index 0000000..21e8078
--- /dev/null
+++ b/commands/enabled.go
@@ -0,0 +1,13 @@
+package commands
[...]
```

However, there's nothing weird in master branch.

**To switch to other branch we can use:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Chandi-Bot/Chandi-Bot)-[2023.04.02|16:14:38(HKT)]-[git://master ✔]
└> git checkout fix-packages            
branch 'fix-packages' set up to track 'origin/fix-packages'.
Switched to a new branch 'fix-packages'
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Chandi-Bot/Chandi-Bot)-[2023.04.02|16:14:46(HKT)]-[git://fix-packages ✔]
└> 
```

**Then, view commit logs again:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Chandi-Bot/Chandi-Bot)-[2023.04.02|16:14:46(HKT)]-[git://fix-packages ✔]
└> git log -p
[...]
diff --git a/commands/main.go b/commands/main.go
index 477d7d4..edb5dc4 100644
--- a/commands/main.go
+++ b/commands/main.go
@@ -82,6 +82,6 @@ func StartScheduledTasks() {
 
 func StopScheduledTasks() {
        if len(ScheduledEvents) > 0 {
-               quit <- "RS{GIT_CHECKOUT_THIS_FLAG}"
+               quit <- "kill"
        }
 }
[...]
```

Boom! We found the flag!

- **Flag: `RS{GIT_CHECKOUT_THIS_FLAG}`**

## Conclusion

What we've learned:

1. Extracting Hidden Information In An Image File
2. Exploiting Logic Vulnerability
3. Leaking Sensitive Information In Git Repository