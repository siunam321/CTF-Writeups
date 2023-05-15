# Blogodogo 1/2

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)

## Overview

- 44 solves / 417 points
- Difficulty: Medium
- Overall difficulty for me (From 1-10 stars): ★★★★★★★★★★

## Background

Try to see the content of the secret note of the administator user.  
  
You can deploy an instance on : **[https://deploy.heroctf.fr](https://deploy.heroctf.fr)**  
Format : **Hero{flag}**  
Author : **xanhacks**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230514215011.png)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513195827.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513195917.png)

A typical blog page.

**In here, we can see the `admin` user:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230514215043.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230514215050.png)

And he has a secret blog post!

**When we click one of those posts, we can report a post:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230514215144.png)

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/Web/Blogodogo-1/blog.zip):**
```shell
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/Web/Blogodogo-1-2)-[2023.05.13|19:59:40(HKT)]
└> file blog.zip 
blog.zip: Zip archive data, at least v2.0 to extract, compression method=store
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/Web/Blogodogo-1-2)-[2023.05.13|19:59:41(HKT)]
└> unzip blog.zip      
Archive:  blog.zip
   creating: blogodogo/
  inflating: blogodogo/requirements.txt  
  inflating: blogodogo/docker-compose.yml  
  inflating: blogodogo/config.py     
   creating: blogodogo/templates/
   creating: blogodogo/templates/pages/
  inflating: blogodogo/templates/pages/add_post.html  
  inflating: blogodogo/templates/pages/register.html  
  inflating: blogodogo/templates/pages/index.html  
  inflating: blogodogo/templates/pages/404.html  
  inflating: blogodogo/templates/pages/profile.html  
  inflating: blogodogo/templates/pages/author.html  
  inflating: blogodogo/templates/pages/about.html  
  inflating: blogodogo/templates/pages/login.html  
  inflating: blogodogo/templates/pages/post.html  
   creating: blogodogo/templates/components/
  inflating: blogodogo/templates/components/flash.html  
  inflating: blogodogo/templates/components/footer.html  
  inflating: blogodogo/templates/components/base.html  
  inflating: blogodogo/templates/components/header.html  
  inflating: blogodogo/templates/components/navbar.html  
   creating: blogodogo/static/
   creating: blogodogo/static/assets/
  inflating: blogodogo/static/assets/favicon.ico  
   creating: blogodogo/static/assets/img/
  inflating: blogodogo/static/assets/img/about-bg.jpg  
  inflating: blogodogo/static/assets/img/contact-bg.jpg  
  inflating: blogodogo/static/assets/img/home-bg.jpg  
  inflating: blogodogo/static/assets/img/post-bg.jpg  
  inflating: blogodogo/static/assets/img/post-sample-image.jpg  
   creating: blogodogo/static/css/
  inflating: blogodogo/static/css/styles.css  
   creating: blogodogo/static/js/
  inflating: blogodogo/static/js/scripts.js  
   creating: blogodogo/src/
  inflating: blogodogo/src/routes.py  
  inflating: blogodogo/src/models.py  
  inflating: blogodogo/src/utils.py  
  inflating: blogodogo/src/__init__.py  
  inflating: blogodogo/src/forms.py  
   creating: blogodogo/bot/
  inflating: blogodogo/bot/bot.js    
  inflating: blogodogo/bot/package.json  
  inflating: blogodogo/Dockerfile    
  inflating: blogodogo/app.py
```

**POST route `/post/report`:**
```python
@bp_routes.route("/post/report", methods=["POST"])
def report_post():
    url = request.form.get("url", "")

    if not re.match("^http://localhost:5000/.*", url):
        flash("URL not valid, please match: ^http://localhost:5000/.*", "warning")
        return redirect(url_for('bp_routes.index'))

    subprocess.run(["node", "/app/bot/bot.js", url])
    flash("Your request has been sent to an administrator!", "success")
    return redirect(url_for('bp_routes.index'))
```

This route will check the URL parameter is starts with `http://localhost:5000/` via regular expression (regex).

**`/app/bot/bot.js`:**
```js
// required packages
const puppeteer = require("puppeteer");

// variables
const host = process.env.HOST;
const adminUsername = process.env.ADMIN_USERNAME;
const adminPassword = process.env.ADMIN_PASSWORD;

// sleep
const delay = (time) => {
    return new Promise(resolve => setTimeout(resolve, time));
}

// navigate
async function goto(url) {
	const browser = await puppeteer.launch({
		headless: true,
		ignoreHTTPSErrors: true,
		args: [ "--no-sandbox", "--ignore-certificate-errors" ],
		executablePath: "/usr/bin/chromium-browser"
	});

	const page = await browser.newPage();
	await page.setDefaultNavigationTimeout(5000);

    // Setup bot context
    await page.goto(host + "/login");
	const username = await page.waitForSelector("#username");
	const password = await page.waitForSelector("#password");
	await username.type(adminUsername);
	await password.type(adminPassword);
	await page.keyboard.press("Enter");
    await page.waitForNavigation();

    // Go to provided URL
	try {
	    await page.goto(url);
	} catch {}

    await delay(1000);

    browser.close();
	return;
}

if (process.argv.length === 2) {
    console.error("No URL provided!");
    process.exit(1);
}

goto(process.argv[2]);
```

If the regex pattern is matched, **it'll let the bot login as `admin`, and go to the provided URL.**

**Then, in GET route `/post/<string:slug>`:**
```python
@bp_routes.route("/post/<string:slug>", methods=["GET"])
def view_post(slug):
    post = Posts.query.filter(Posts.slug == slug).first()

    if not post:
        flash("This post does not exists.", "warning")
        return redirect(url_for('bp_routes.index')) 

    if post.draft and (not current_user.is_authenticated or post.author_id != current_user.id):
        flash("You cannot see draft of other users.", "warning")
        return redirect(url_for('bp_routes.index')) 

    author = Authors.query.filter_by(id=post.author_id).first()
    return render_template("pages/post.html", title="View a post", post=post, author=author)
```

**If the post is in draft, and we're authenticated or the draft's author ID is equal to the current user's ID, we can view the draft's post.**

That being said, **we need to somehow redirect the `admin` bot to the secret blog post, and exfiltrate the content of that draft post.**

But how?

**In GET route `/post/preview/<string:hash_preview>`, we can get a preview of a post:**
```python
@bp_routes.route("/post/preview/<string:hash_preview>", methods=["GET"])
def preview_post(hash_preview):
    post = Posts.query.filter_by(hash_preview=hash_preview).first()

    if post:
        author = Authors.query.filter_by(id=post.author_id).first()
        return render_template("pages/post.html", title="Preview a post", post=post, author=author)

    flash("Unable to find the corresponding post.", "warning")
    return redirect(url_for('bp_routes.index'))
```

But how can we get the `hash_preview` value?

Hmm... Maybe if we can exploit Server-Side Request Forgery (SSRF) in the `/post/report`, we could view the secret blog post?

No clue about that...