# Exploiting clickjacking vulnerability to trigger DOM-based XSS

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/clickjacking/lab-exploiting-to-trigger-dom-based-xss), you'll learn: Exploiting clickjacking vulnerability to trigger DOM-based XSS! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains an [XSS](https://portswigger.net/web-security/cross-site-scripting) vulnerability that is triggered by a click. Construct a [clickjacking attack](https://portswigger.net/web-security/clickjacking) that fools the user into clicking the "Click me" button to call the `print()` function.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-4/images/Pasted%20image%2020230102061525.png)

**Feedback page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-4/images/Pasted%20image%2020230102061621.png)

In here, we can submit a feedback to the back-end.

Let's try to submit a test feedback:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-4/images/Pasted%20image%2020230102061700.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-4/images/Pasted%20image%2020230102061708.png)

When we clicked the "Submit feedback" button, it'll display our name.

**View source page:**
```html
<form id="feedbackForm" action="/feedback/submit" method="POST" enctype="application/x-www-form-urlencoded" personal="true">
    <input required type="hidden" name="csrf" value="BX4Ak51cXyol4PcY7g5vtLn4JKtYucEo">
    <label>Name:</label>
    <input required type="text" name="name">
    <label>Email:</label>
    <input required type="email" name="email">
    <label>Subject:</label>
    <input required type="text" name="subject">
    <label>Message:</label>
    <textarea required rows="12" cols="300" name="message"></textarea>
    <button class="button" type="submit">
        Submit feedback
    </button>
    <span id="feedbackResult"></span>
</form>
<script src="/resources/js/submitFeedback.js"></script>
```

**`/resources/js/submitFeedback.js`:**
```js
document.getElementById("feedbackForm").addEventListener("submit", function(e) {
    submitFeedback(this.getAttribute("method"), this.getAttribute("action"), this.getAttribute("enctype"), this.getAttribute("personal"), new FormData(this));
    e.preventDefault();
});

function submitFeedback(method, path, encoding, personal, data) {
    var XHR = new XMLHttpRequest();
    XHR.open(method, path);
    if (personal) {
        XHR.addEventListener("load", displayFeedbackMessage(data.get('name')));
    } else {
        XHR.addEventListener("load", displayFeedbackMessage());
    }
    if (encoding === "multipart/form-data") {
        XHR.send(data)
    } else {
        var params = new URLSearchParams(data);
        XHR.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        XHR.send(params.toString())
    }
}

function displayFeedbackMessage(name) {
    return function() {
        var feedbackResult = document.getElementById("feedbackResult");
        if (this.status === 200) {
            feedbackResult.innerHTML = "Thank you for submitting feedback" + (name ? ", " + name : "") + "!";
            feedbackForm.reset();
        } else {
            feedbackResult.innerHTML =  "Failed to submit feedback: " + this.responseText
        }
    }
}
```

**In here, function `displayFeedbackMessage(name)` looks interesting:**
```js
feedbackResult.innerHTML = "Thank you for submitting feedback" + (name ? ", " + name : "") + "!";
```

It's using **`innerHTML` sink** (Dangerous function), and **our source (user input) is directly parsed to that sink without HTML encoded, escaped, sanitized.**

**That being said, if the back-end didn't do any input validations, it's very likely to be vulnerable to DOM-based XSS (Cross-Site Scripting).**

**Let's test for XSS in the `name` field:**
```html
<img src=errorpls onerror=alert(document.domain)>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-4/images/Pasted%20image%2020230102062501.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-4/images/Pasted%20image%2020230102062509.png)

Nice! We successfully exploited DOM-based XSS.

**Now, we can combine DOM-based XSS and clickjacking.**

**First, we need to prepopulate the XSS payload via providing a GET parameter `name` and other required parameters:**
```
/feedback?name=<img src=errorpls onerror=print()>&email=attacker@evil.com&subject=subject&message=message
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-4/images/Pasted%20image%2020230102063102.png)

Then, we can **craft the HTML payload that tricks users to click on the "Submit feedback" button**.

However, instead of crafting it manually, we can use **Burp Suite's Clickbandit**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-4/images/Pasted%20image%2020230102063315.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-4/images/Pasted%20image%2020230102063323.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-4/images/Pasted%20image%2020230102063341.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-4/images/Pasted%20image%2020230102063351.png)

Click "Start":

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-4/images/Pasted%20image%2020230102063413.png)

Click the "Submit feedback" button:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-4/images/Pasted%20image%2020230102063434.png)

Then click the "Finish" button:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-4/images/Pasted%20image%2020230102063452.png)

After that, **turn off transparency**, and click "Save":

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-4/images/Pasted%20image%2020230102063506.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-4/images/Pasted%20image%2020230102063544.png)

Now we can test it works or not:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-4/images/Pasted%20image%2020230102063612.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-4/images/Pasted%20image%2020230102063620.png)

It worked!

**Finally, go to exploit server to host our clickjacking payload, and deilver to victim:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-4/images/Pasted%20image%2020230102063738.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-4/images/Pasted%20image%2020230102063747.png)

Nice!

# What we've learned:

1. Exploiting clickjacking vulnerability to trigger DOM-based XSS