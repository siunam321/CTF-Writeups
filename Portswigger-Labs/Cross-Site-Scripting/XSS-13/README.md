# Stored DOM XSS

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-dom-xss-stored), you'll learn: Stored DOM XSS! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab demonstrates a stored DOM vulnerability in the blog comment functionality. To solve this lab, exploit this vulnerability to call the `alert()` function.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-13/images/Pasted%20image%2020221230071253.png)

**In the home page, we can view one of those blogs:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-13/images/Pasted%20image%2020221230071319.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-13/images/Pasted%20image%2020221230071327.png)

And we can leave some comments.

**View source page:**
```html
<h1>Comments</h1>
<span id='user-comments'>
<script src='resources/js/loadCommentsWithVulnerableEscapeHtml.js'></script>
<script>loadComments('/post/comment')</script>
</span>
```

**`resources/js/loadCommentsWithVulnerableEscapeHtml.js`:**
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

    function escapeHTML(html) {
        return html.replace('<', '&lt;').replace('>', '&gt;');
    }

    function displayComments(comments) {
        let userComments = document.getElementById("user-comments");

        for (let i = 0; i < comments.length; ++i)
        {
            comment = comments[i];
            let commentSection = document.createElement("section");
            commentSection.setAttribute("class", "comment");

            let firstPElement = document.createElement("p");

            let avatarImgElement = document.createElement("img");
            avatarImgElement.setAttribute("class", "avatar");
            avatarImgElement.setAttribute("src", comment.avatar ? escapeHTML(comment.avatar) : "/resources/images/avatarDefault.svg");

            if (comment.author) {
                if (comment.website) {
                    let websiteElement = document.createElement("a");
                    websiteElement.setAttribute("id", "author");
                    websiteElement.setAttribute("href", comment.website);
                    firstPElement.appendChild(websiteElement)
                }

                let newInnerHtml = firstPElement.innerHTML + escapeHTML(comment.author)
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

            firstPElement.appendChild(avatarImgElement);

            commentSection.appendChild(firstPElement);

            if (comment.body) {
                let commentBodyPElement = document.createElement("p");
                commentBodyPElement.innerHTML = escapeHTML(comment.body);

                commentSection.appendChild(commentBodyPElement);
            }
            commentSection.appendChild(document.createElement("p"));

            userComments.appendChild(commentSection);
        }
    }
};
```

**In line 5, the `comments` variable is parsing an JSON object:**
```js
let comments = JSON.parse(this.responseText);
```

**Then in line 12-14, we can see that it's escaping HTML code:**
```js
function escapeHTML(html) {
    return html.replace('<', '&lt;').replace('>', '&gt;');
}
```

**The `<` and `>` will be replaced as `&lt;` and `&gt;`.**

We also see that the JavaScript file uses `innerHTML` in `comment.author`, `comment.body`, which is a sink (Dangerous function).

```js
let newInnerHtml = firstPElement.innerHTML + escapeHTML(comment.author)
```

Armed with above information, we can start to bypass the `<>` HTML encoding.

According to [W3School](https://www.w3schools.com/jsref/jsref_replace.asp), **the `replace()` method only replace the first instance.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-13/images/Pasted%20image%2020221230073253.png)

Which means if we add more than 1 `<` or `>`, it'll be ignored.

**Let's craft the XSS payload:**
```
<><img src=errorpls onerror=alert(document.domain)>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-13/images/Pasted%20image%2020221230073659.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-13/images/Pasted%20image%2020221230073706.png)

Nice!