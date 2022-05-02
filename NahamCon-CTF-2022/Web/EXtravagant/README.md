# Background
![background](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Web/Extravagant/images/background.png)

In this challenge, you'll learn more about `XXE(XML external entity injection)`. As usual, let's start the instance via the Start button on the top-right, and browse the website.

![soltion1](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Web/Extravagant/images/solution1.png)

In the `about` page, we can see the site is using `XML parsing`, and we can upload a simple in `Trial` page, and view it on the `View XML` page. Hmm... Maybe we can do a `XXE, or XML external entity injection`?? Next, I started to google `XXE file upload exploit`, and I found one PDF explaining that exploit in **[exploit-db](https://www.exploit-db.com/docs/49732)**. It said:

> **"if the application allows user to upload svg files on the system, then the XXE can be exploited using them, and a SVG file is to define graphics in XML format."**

Then I found a **XXE inside SVG upload payload** at [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/README.md).

Let's copy and paste it to our text editor. Also, **According to the background of this challenge, the flag is in /var/www**, so let's modify the path from "file:///etc/hostname" to `"file:///var/www/flag.txt"`

![soltion2](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Web/Extravagant/images/solution2.png)

Now, upload the SVG file to `Trial` page.

![soltion3](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Web/Extravagant/images/solution3.png)

![soltion4](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Web/Extravagant/images/solution4.png)

Upload successful!! Let's go to the `View XML` page to see is it work!

![soltion5](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Web/Extravagant/images/solution5.png)

![flag](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Web/Extravagant/images/flag.png)

Yes!! We've the flag!