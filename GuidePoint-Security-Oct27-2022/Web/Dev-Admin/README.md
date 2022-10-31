# Dev Admin

## Overview

- Overall difficulty for me: Very easy

**In this challenge, we can spawn a docker instance:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029003813.png)

## Find the flag

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029003849.png)

The reason why it said `Not Authorized!`, is becase **when we go to this page (`index.php`), it sets a cookie for us**!

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029004110.png)

**We have a cookie is set, and the key name called `dev_session`!**

**The `%3D` is URL encoded, let's decode that:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029004213.png)

**It's a base64 encoded string! Let's decode that via `base64 -d`!**
```
┌──(root🌸siunam)-[~/ctf/GuidePoint-Security-Oct27-2022/Web/Dev-Admin]
└─# echo "YWRtaW5pc3RyYXRvcjpmYWxzZQ==" | base64 -d
administrator:false
```

**Nice! What if we set the `false` value to `true`?? Will I become authorized?**

**To do so, I'll reverse the above processes:** (`-n` for no new line character)
```
┌──(root🌸siunam)-[~/ctf/GuidePoint-Security-Oct27-2022/Web/Dev-Admin]
└─# echo -n "administrator:true" | base64          
YWRtaW5pc3RyYXRvcjp0cnVl
```

**Edit the cookie:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029004424.png)

**Then hard refresh the page: (`Ctrl + Shift + R`)**

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221029004450.png)

We got the flag!

# Conclusion

What we've learned:

1. Authentication Bypass via Weak Cookie Value