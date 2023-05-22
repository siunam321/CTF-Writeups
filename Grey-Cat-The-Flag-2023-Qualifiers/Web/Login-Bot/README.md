# Login Bot

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- 77 solves / 50 points
- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

I made a reverse blog where anyone can blog but only I can see it (Opposite of me blogging and everyone seeing). You can post your content with my bot and I'll read it.

Sometimes weird errors happen and the bot gets stuck. I've fixed it now so it should work!

- Junhua

[http://34.124.157.94:5002](http://34.124.157.94:5002)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/images/Pasted%20image%2020230519220700.png)

When we go to `/`, it redirects us to `/login` route, with GET parameter `next`.

**Since we're dealing with a login page in here, we could try some simple SQL injection to bypass the authentication, like `'OR 1=1-- -`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/images/Pasted%20image%2020230519220814.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/images/Pasted%20image%2020230519220819.png)

Nope.

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/Web/Login-Bot/dist.zip):**
```shell
┌[siunam♥earth]-(~/ctf/Grey-Cat-The-Flag-2023-Qualifiers/Web/Login-Bot)-[2023.05.19|22:08:50(HKT)]
└> file dist.zip 
dist.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥earth]-(~/ctf/Grey-Cat-The-Flag-2023-Qualifiers/Web/Login-Bot)-[2023.05.19|22:08:51(HKT)]
└> unzip dist.zip           
Archive:  dist.zip
  inflating: docker-compose.yml      
  inflating: login/app.py            
  inflating: login/dockerfile        
  inflating: login/requirements.txt  
  inflating: login/templates/base.html  
  inflating: login/templates/index.html  
  inflating: login/templates/login.html  
  inflating: login/templates/send_post.html  
  inflating: login/utils.py          
  inflating: nginx/dockerfile        
  inflating: nginx/nginx.conf        
```

After reading all the source code, we can focus on some important routes.

**`/login/app.py`'s route `/send_post`:**
```python
@app.route('/send_post', methods=['GET', 'POST'])
def send_post() -> Response:
    """Send a post to the admin"""
    if request.method == 'GET':
        return render_template('send_post.html')

    url = request.form.get('url', '/')
    title = request.form.get('title', None)
    content = request.form.get('content', None)

    if None in (url, title, content):
        flash('Please fill all fields', 'danger')
        return redirect(url_for('send_post'))
    
    # Bot visit
    url_value = make_post(url, title, content)
    flash('Post sent successfully', 'success')
    flash('Url id: ' + str(url_value), 'info')
    return redirect('/send_post')
```

In here, when we send a POST request to `/send_post`, it'll take POST parameter `url`, `title`, `content`, the `url` parameter default is `/`.

**Then, it'll call function `make_post()`:**
```python
BASE_URL = f"http://localhost:5000"
[...]
def make_post(url: str, title: str, user_content: str) -> int:
    """Make a post to the admin"""
    with requests.Session() as s:
        visit_url = f"{BASE_URL}/login?next={url}"
        resp = s.get(visit_url, timeout=10)
        content = resp.content.decode('utf-8')
        
        # Login routine (If website is buggy we run it again.)
        for _ in range(2):
            print('Logging in... at:', resp.url, file=sys.stderr)
            if "bot_login" in content:
                # Login routine
                resp = s.post(resp.url, data={
                    'username': 'admin',
                    'password': FLAG,
                })

        # Make post
        resp = s.post(f"{resp.url}/post", data={
            'title': title,
            'content': user_content,
        })

        return db.session.query(Url).count()
```

The `visit_url` will be: `http://localhost:5000/login?next={url}`. The `next` GET parameter is to redirect user after logged in. So we basically have **Open Redirect vulnerability**.

***This function will login as user `admin` twice.***

**It'll also create a new post as the `admin` bot user via route `post`:**
```python
@app.route('/post', methods=['POST'])
def post() -> Response:
    if not is_admin():
        flash('You are not an admin. Please login to continue', 'danger')
        return redirect(f'/login?next={request.path}')


    title = request.form['title']
    content = request.form['content']

    sanitized_content = sanitize_content(content)

    if title and content:
        post = Post(title=title, content=sanitized_content)
        db.session.add(post)
        db.session.commit()
        flash('Post created successfully', 'success')
        return redirect(url_for('index'))

    flash('Please fill all fields', 'danger')
    return redirect(url_for('index'))
```

**However, before the post is created, it first sanitizes our provided `content` POST parameter via function `sanitize_content()`:**
```python
URL_REGEX = r'(https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*))'
[...]
class Url(db.Model):
    id = Column(Integer, primary_key=True, autoincrement=True)
    url = Column(String(100), nullable=False)
[...]
def sanitize_content(content: str) -> str:
    """Sanitize the content of the post"""

    # Replace URLs with in house url tracker
    urls = re.findall(URL_REGEX, content)
    for url in urls:
        url = url[0]
        url_obj = Url(url=url)
        db.session.add(url_obj)
        content = content.replace(url, f"/url/{url_obj.id}")
    return content
```

This function will find all the URLs with the regex (Regular Expression). The regex pattern looks terrifying, but it's basically finding pattern: `http(s)://example.com/file_here`.

Then, it'll crete a new object instance `url_obj` from class `Url`, and initialize the `url` attribute to the URL that matches the regex pattern.

Next, it'll add the `url_obj` to SQLite database.

Finally, our `content`'s value is replaced by `/url/{url_obj.id}`.

**Route `/url/<int:id>`:**
```python
@app.route('/url/<int:id>')
def url(id: int) -> Response:
    """Redirect to the url in post if its sanitized"""
    url = Url.query.get_or_404(id)
    return redirect(url.url)
```

In this route, we can provide an ID (From `url_obj.id`), and it'll try to fetch the `url_obj` object instance with the ID.

After that, it'll redirect us to the `url_obj` object instance's `url` attribute's value.

## Exploitation

After reading through all the source code, we can see that:

- If our `content` POST parameter's value contains a URL, **it'll add the URL in the `url_obj.url`**
- Route `/url/<int:id>` doesn't need to be authenticated
- Open Redirect vulnerability in `next` GET parameter in `/login` route

**Armed with above information, we can create 2 new posts:**

**The first new post has the `content` POST parameter, which contains a [webhook.site](webhook.site)'s URL, which will be added in the  `url_obj.url`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/images/Pasted%20image%2020230520114738.png)

It returned the Url id `205` from object instance `url_obj`.

**The second new post we need to provide the `url` POST parameter with value `http://localhost:5000/url/{id}`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/images/Pasted%20image%2020230520114938.png)

**This will redirect the `admin` bot to our webhook URL via `next` GET parameter, which will then send a login POST request to our webhook URL:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/images/Pasted%20image%2020230520115125.png)

Nice! We successfully captured the `admin` bot's password!!

- **Flag: `grey{r3d1recTs_r3Dir3cts_4nd_4ll_0f_th3_r3d1r3ct5}`**
- Credits: @7777777

## Conclusion

What we've learned:

1. Exploiting Open Redirect Vulnerability To Leak Credentials