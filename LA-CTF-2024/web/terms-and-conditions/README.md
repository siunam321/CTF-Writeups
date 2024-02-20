# terms-and-conditions

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Get the Flag](#get-the-flag)
5. [Conclusion](#conclusion)

## Overview

- 771 solves / 106 points
- Author: aplet123
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Welcome to LA CTF 2024! All you have to do is accept the terms and conditions and you get a flag!

[terms-and-conditions.chall.lac.tf](https://terms-and-conditions.chall.lac.tf)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219085607.png)

## Enumeration

**Index page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219090047.png)

In here, we can see that there's a button called "I Accept".

However, when my cursor gets closer to the button, **the button goes away from my cursor**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219090903.png)

Hmm... Why?

**Well, if you view the source by using key `Ctrl + U`, you can see some JavaScript code:**
```html
            [...]
            <button tabindex="-1" id="accept">I Accept</button>
        [...]
        <script defer src="/analytics.js"></script>
        [...]
        <script id="mainscript">
            const accept = document.getElementById("accept");
            document.body.addEventListener("touchstart", (e) => {
                document.body.innerHTML = "<div><h1>NO TOUCHING ALLOWED</h1></div>";
            });
            let tx = 0;
            let ty = 0;
            let mx = 0;
            let my = 0;
            window.addEventListener("mousemove", function (e) {
                mx = e.clientX;
                my = e.clientY;
            });
            setInterval(function () {
                const rect = accept.getBoundingClientRect();
                const cx = rect.x + rect.width / 2;
                const cy = rect.y + rect.height / 2;
                const dx = mx - cx;
                const dy = my - cy;
                const d = Math.hypot(dx, dy);
                const mind = Math.max(rect.width, rect.height) + 10;
                const safe = Math.max(rect.width, rect.height) + 25;
                if (d < mind) {
                    const diff = mind - d;
                    if (d == 0) {
                        tx -= diff;
                    } else {
                        tx -= (dx / d) * diff;
                        ty -= (dy / d) * diff;
                    }
                } else if (d > safe) {
                    const v = 2;
                    const offset = Math.hypot(tx, ty);
                    const factor = Math.min(v / offset, 1);
                    if (offset > 0) {
                        tx -= tx * factor;
                        ty -= ty * factor;
                    }
                }
                accept.style.transform = `translate(${tx}px, ${ty}px)`;
            }, 1);
            let width = window.innerWidth;
            let height = window.innerHeight;
            setInterval(function() {
                if (window.innerHeight !== height || window.innerWidth !== width) {
                    document.body.innerHTML = "<div><h1>NO CONSOLE ALLOWED</h1></div>";
                    height = window.innerHeight;
                    width = window.innerWidth;
                }
            }, 10);
        </script>
        [...]
```

**More specifically, take a look at the following JavaScript code:** 
```javascript
const accept = document.getElementById("accept");
document.body.addEventListener("touchstart", (e) => {
    document.body.innerHTML = "<div><h1>NO TOUCHING ALLOWED</h1></div>";
});
```

First, get the `<button>` element with id `accept` by using DOM (Document Object Model) method `getElementById()`. Then, the JavaScript adds an event called [`touchstart`](https://developer.mozilla.org/en-US/docs/Web/API/Element/touchstart_event) to that button. When there's a `touchstart` event is being fired, the HTML body text change to `<div><h1>NO TOUCHING ALLOWED</h1></div>`.

According to [https://www.w3schools.com/jsref/event_touchstart.asp](https://www.w3schools.com/jsref/event_touchstart.asp), the `touchstart` event only works on touch screens. So, if we're using touch screen to touch the accept button, the body text will be changed to the "`NO TOUCHING ALLOWED`".

**Next, we can see why the accept button is moving away from our cursor:**
```javascript
let tx = 0;
let ty = 0;
let mx = 0;
let my = 0;
window.addEventListener("mousemove", function (e) {
    mx = e.clientX;
    my = e.clientY;
});
setInterval(function () {
    const rect = accept.getBoundingClientRect();
    const cx = rect.x + rect.width / 2;
    const cy = rect.y + rect.height / 2;
    const dx = mx - cx;
    const dy = my - cy;
    const d = Math.hypot(dx, dy);
    const mind = Math.max(rect.width, rect.height) + 10;
    const safe = Math.max(rect.width, rect.height) + 25;
    if (d < mind) {
        const diff = mind - d;
        if (d == 0) {
            tx -= diff;
        } else {
            tx -= (dx / d) * diff;
            ty -= (dy / d) * diff;
        }
    } else if (d > safe) {
        const v = 2;
        const offset = Math.hypot(tx, ty);
        const factor = Math.min(v / offset, 1);
        if (offset > 0) {
            tx -= tx * factor;
            ty -= ty * factor;
        }
    }
    accept.style.transform = `translate(${tx}px, ${ty}px)`;
}, 1);
```

In here, the event [`mousemove`](https://developer.mozilla.org/en-US/docs/Web/API/Element/mousemove_event) has been added to the accept button. As the event name says, it's fired when the mouse is moving. In our case, when we move the mouse/cursor, it tracks our cursor's X (`e.clientX`) and Y (`e.clientY`) position.

Then, by using global function `setInterval()`, every 1 millisecond **it'll check our cursor position is within the safe zone of the accept button's position**. If not, it uses CSS style to change the position of the accept button (`translate()`).

Hmm... How can we click the accept button without touching/getting near it??

**If you take a closer look at the last pieces of the index page's JavaScript code, you'll find something called "browser console":**
```javascript
let width = window.innerWidth;
let height = window.innerHeight;
setInterval(function() {
    if (window.innerHeight !== height || window.innerWidth !== width) {
        document.body.innerHTML = "<div><h1>NO CONSOLE ALLOWED</h1></div>";
        height = window.innerHeight;
        width = window.innerWidth;
    }
}, 10);
```

In here, for every 10 milliseconds, if our **current window's height and width** is **not the same as the newly retrieved one**, our body HTML will become `<div><h1>NO CONSOLE ALLOWED</h1></div>`.

However, when we **refresh the page**, not only the browser console is still there, **but also the check will not get passed**.

When we refresh the page, our `width` and `height` is the window size with the browser console, so when the JavaScript retrieve our window size again, the width and height is the same as our current window size.

## Get the Flag

**Now, in Firefox, you can open the browser console via hitting `F12`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219094334.png)

As expected, our current window size has been changed when the browser console appeared.

However, when we refresh the page, our body HTML won't change to `NO CONSOLE ALLOWED`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219094925.png)

Now, we can **click the accept button with JavaScript code**!

But before we do that, let's try to understand what will happen when we click that button.

**During view the index page's source page, there's another JavaScript file has been loaded:**
```html
<script defer src="/analytics.js"></script>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219095403.png)

Oh boy... It's obfuscated... And I don't want to deobfuscate it...

> Obfuscation is a technique that turns the code into a very unreadable way.

Anway, let's just click the accept button.

In JavaScript's DOM, there's a method called **[`click()`](https://developer.mozilla.org/en-US/docs/Web/API/HTMLElement/click)**, which allows us to click an element.

Since the accept button has already declared (See the 1 line above the `touchstart` event), there's no need to declare it again or get the element with DOM method [`getElementById()`](https://developer.mozilla.org/en-US/docs/Web/API/Document/getElementById).

**Hence, we can click the accept button by typing the following JavaScript code in the browser console:**
```javascript
accept.click()
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219100148.png)

Here we go! There's the flag!

- **Flag: `lactf{that_button_was_definitely_not_one_of_the_terms}`**

## Conclusion

What we've learned:

1. Debugging via browser console