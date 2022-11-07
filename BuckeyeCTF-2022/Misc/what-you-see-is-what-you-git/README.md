# what-you-see-is-what-you-git

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

> I definitely made a Git repo, but I somehow broke it. Something about not getting a HEAD of myself.

> Author: matthewa26

> Difficulty: Beginner

## Find the flag

**In this challenge, we can download a file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221106011621.png)

```
┌──(root🌸siunam)-[~/ctf/BuckeyeCTF-2022/Misc/what-you-see-is-what-you-git]
└─# unzip what-you-see-is-what-you-git.zip 
Archive:  what-you-see-is-what-you-git.zip
   creating: what-u-see-is-what-u-git/
  inflating: what-u-see-is-what-u-git/flag  
   creating: what-u-see-is-what-u-git/.git/
  inflating: what-u-see-is-what-u-git/.git/config  
   creating: what-u-see-is-what-u-git/.git/objects/
  inflating: what-u-see-is-what-u-git/.git/HEAD  
   creating: what-u-see-is-what-u-git/.git/info/
   creating: what-u-see-is-what-u-git/.git/logs/
  inflating: what-u-see-is-what-u-git/.git/description  
   creating: what-u-see-is-what-u-git/.git/hooks/
   creating: what-u-see-is-what-u-git/.git/refs/
  inflating: what-u-see-is-what-u-git/.git/index  
  inflating: what-u-see-is-what-u-git/.git/COMMIT_EDITMSG  
   creating: what-u-see-is-what-u-git/.git/objects/02/
   creating: what-u-see-is-what-u-git/.git/objects/a4/
   creating: what-u-see-is-what-u-git/.git/objects/bb/
   creating: what-u-see-is-what-u-git/.git/objects/bd/
   creating: what-u-see-is-what-u-git/.git/objects/fe/
   creating: what-u-see-is-what-u-git/.git/objects/ed/
   creating: what-u-see-is-what-u-git/.git/objects/pack/
   creating: what-u-see-is-what-u-git/.git/objects/7c/
   creating: what-u-see-is-what-u-git/.git/objects/info/
   creating: what-u-see-is-what-u-git/.git/objects/30/
   creating: what-u-see-is-what-u-git/.git/objects/ba/
   creating: what-u-see-is-what-u-git/.git/objects/c4/
   creating: what-u-see-is-what-u-git/.git/objects/7a/
  inflating: what-u-see-is-what-u-git/.git/info/exclude  
  inflating: what-u-see-is-what-u-git/.git/logs/HEAD  
   creating: what-u-see-is-what-u-git/.git/logs/refs/
  inflating: what-u-see-is-what-u-git/.git/hooks/commit-msg.sample  
  inflating: what-u-see-is-what-u-git/.git/hooks/pre-rebase.sample  
  inflating: what-u-see-is-what-u-git/.git/hooks/pre-commit.sample  
  inflating: what-u-see-is-what-u-git/.git/hooks/applypatch-msg.sample  
  inflating: what-u-see-is-what-u-git/.git/hooks/fsmonitor-watchman.sample  
  inflating: what-u-see-is-what-u-git/.git/hooks/pre-receive.sample  
  inflating: what-u-see-is-what-u-git/.git/hooks/prepare-commit-msg.sample  
  inflating: what-u-see-is-what-u-git/.git/hooks/post-update.sample  
  inflating: what-u-see-is-what-u-git/.git/hooks/pre-merge-commit.sample  
  inflating: what-u-see-is-what-u-git/.git/hooks/pre-applypatch.sample  
  inflating: what-u-see-is-what-u-git/.git/hooks/pre-push.sample  
  inflating: what-u-see-is-what-u-git/.git/hooks/update.sample  
  inflating: what-u-see-is-what-u-git/.git/hooks/push-to-checkout.sample  
   creating: what-u-see-is-what-u-git/.git/refs/heads/
   creating: what-u-see-is-what-u-git/.git/refs/tags/
  inflating: what-u-see-is-what-u-git/.git/objects/02/417f390d6d72ad68082cd243760461aa3bd42a  
  inflating: what-u-see-is-what-u-git/.git/objects/a4/2fb0aff66b5c17f715d14e19e0c12ee1c39ad7  
  inflating: what-u-see-is-what-u-git/.git/objects/bb/d93721bb5fc59892898f94dc9ef6a59d4fa7e6  
  inflating: what-u-see-is-what-u-git/.git/objects/bd/a12cdd4a21faa0144861b9588f8bb1f64faa15  
  inflating: what-u-see-is-what-u-git/.git/objects/fe/6f925cc960a35e5615d5988004ca9b6345469f  
  inflating: what-u-see-is-what-u-git/.git/objects/ed/1555daddda018ab29e354a2a1e2f703a9a16bc  
  inflating: what-u-see-is-what-u-git/.git/objects/7c/a1eaa16d3c318b3621d1e70c326c098f71ad2d  
  inflating: what-u-see-is-what-u-git/.git/objects/30/b26c2c7e8d48612cc5f6da4a374e262ccf860c  
  inflating: what-u-see-is-what-u-git/.git/objects/ba/d9216e78dcdad19f7ba3995b05282fd4719ec7  
  inflating: what-u-see-is-what-u-git/.git/objects/c4/681c8d561653cee9ecbea5d5ca5629adfd67a4  
  inflating: what-u-see-is-what-u-git/.git/objects/7a/e8453a76a41d40bdfcc7992175390f70ba9fdf  
   creating: what-u-see-is-what-u-git/.git/logs/refs/heads/
  inflating: what-u-see-is-what-u-git/.git/logs/refs/heads/main  
```

**It's a `git` repository!**

**Let's check any logs there!**
```
┌──(root🌸siunam)-[~/…/BuckeyeCTF-2022/Misc/what-you-see-is-what-you-git/what-u-see-is-what-u-git]
└─# git log
fatal: your current branch 'main' does not have any commits yet
```

Hmm... Nothing?

**However in the `logs/HEAD`, there are some commits!**
```
┌──(root🌸siunam)-[~/…/Misc/what-you-see-is-what-you-git/what-u-see-is-what-u-git/.git]
└─# cat logs/HEAD 
0000000000000000000000000000000000000000 30b26c2c7e8d48612cc5f6da4a374e262ccf860c NOT Gent Semaj  <jim@bo.hacked> 1667608995 -0400	commit (initial): Initial commit
30b26c2c7e8d48612cc5f6da4a374e262ccf860c 02417f390d6d72ad68082cd243760461aa3bd42a Shannon's Man <peanut@butter.jellytime> 1667609597 -0400	commit: Added Andy Warhol effect to file

7ae8453a76a41d40bdfcc7992175390f70ba9fdf c4681c8d561653cee9ecbea5d5ca5629adfd67a4 Matthew Ayers <matt@matthewayers.com> 1667704926 -0400	commit: Hid the flag
```

**Hmm... Looks like the `refs/heads/main` is missing.**
```
┌──(root🌸siunam)-[~/…/Misc/what-you-see-is-what-you-git/what-u-see-is-what-u-git/.git]
└─# cat HEAD                   
ref: refs/heads/main
                                                                                                           
┌──(root🌸siunam)-[~/…/Misc/what-you-see-is-what-you-git/what-u-see-is-what-u-git/.git]
└─# ls -lah refs/heads/ 
total 8.0K
drwxr-xr-x 2 root root 4.0K Nov  5 23:30 .
drwxr-xr-x 4 root root 4.0K Nov  4 20:12 ..
```

**Normal git repositroy:**
```
┌──(root🌸siunam)-[~/gitrepo/CTF-Writeups/.git]
└─# ls refs/heads/             
total 12K
drwxr-xr-x 2 root root 4.0K Nov  3 06:26 .
drwxr-xr-x 5 root root 4.0K Oct 31 05:03 ..
-rw-r--r-- 1 root root   41 Nov  3 06:26 main
```

**Since I have a normal git repository, let's compare both of them.**

**In my normal git repository, the `refs/heads/main` is a hex value, which is the latest commit hash:**
```
┌──(root🌸siunam)-[~/gitrepo/CTF-Writeups/.git]
└─# cat refs/heads/main         
6afd7e3096c026105c7c332ec6f9ef3ad5fab73f
                                                                                                           
┌──(root🌸siunam)-[~/gitrepo/CTF-Writeups/.git]
└─# cat logs/HEAD      
0000000000000000000000000000000000000000 2d6d59bca96e53e8cf1641e452bc8e02b250c71b siunam321 <nambackup20030106@gmail.com> 1667207026 -0400	clone: from github.com:siunam321/CTF-Writeups.git
[...]
3f8bec331d9ccc5cc038f674529fedcad6e7532f 6afd7e3096c026105c7c332ec6f9ef3ad5fab73f siunam321 <nambackup20030106@gmail.com> 1667471177 -0400	commit: Added Templates writeup
```

**However, the challenge's git is missing the latest commit hash!**

**Let's create a new main file before the they hide the flag!!**

**Check all the commits:**
```
┌──(root🌸siunam)-[~/…/Misc/what-you-see-is-what-you-git/what-u-see-is-what-u-git/.git]
└─# cat logs/HEAD 
0000000000000000000000000000000000000000 30b26c2c7e8d48612cc5f6da4a374e262ccf860c NOT Gent Semaj  <jim@bo.hacked> 1667608995 -0400	commit (initial): Initial commit
30b26c2c7e8d48612cc5f6da4a374e262ccf860c 02417f390d6d72ad68082cd243760461aa3bd42a Shannon's Man <peanut@butter.jellytime> 1667609597 -0400	commit: Added Andy Warhol effect to file

7ae8453a76a41d40bdfcc7992175390f70ba9fdf c4681c8d561653cee9ecbea5d5ca5629adfd67a4 Matthew Ayers <matt@matthewayers.com> 1667704926 -0400	commit: Hid the flag
```

**Our target hash is: `c4681c8d561653cee9ecbea5d5ca5629adfd67a4`**

**Create a new main file:**
```
┌──(root🌸siunam)-[~/…/Misc/what-you-see-is-what-you-git/what-u-see-is-what-u-git/.git]
└─# nano refs/heads/main

┌──(root🌸siunam)-[~/…/Misc/what-you-see-is-what-you-git/what-u-see-is-what-u-git/.git]
└─# cat refs/heads/main 
c4681c8d561653cee9ecbea5d5ca5629adfd67a4
```

**Check `git log`:**
```
┌──(root🌸siunam)-[~/…/Misc/what-you-see-is-what-you-git/what-u-see-is-what-u-git/.git]
└─# git log -p
commit c4681c8d561653cee9ecbea5d5ca5629adfd67a4 (HEAD -> main)
Author: Matthew Ayers <matt@matthewayers.com>
Date:   Sat Nov 5 23:22:06 2022 -0400

    Hid the flag

diff --git a/flag b/flag
index 7ca1eaa..bad9216 100644
--- a/flag
+++ b/flag
@@ -1,4 +1,3 @@
-buckeye{G1t_w@S_N@m3D_afT3r_Torvalds}
 buckeye{placeholder_flag}
 buckeye{placeholder_flag}
 buckeye{placeholder_flag}

commit 7ae8453a76a41d40bdfcc7992175390f70ba9fdf
Author: Matthew Ayers <matt@matthewayers.com>
Date:   Fri Nov 4 21:03:43 2022 -0400

    Added more stuff
```

Boom! We sucessfully fixed the broken git repository and found the flag!

# Conclusion

What we've learned:

1. Git Log Forensics