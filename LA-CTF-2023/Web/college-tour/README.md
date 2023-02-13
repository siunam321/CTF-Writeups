# college-tour

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

- 756 solves / 100 points

## Background

> Author: jerry

Welcome to UCLA! To explore the #1 public college, we have prepared a scavenger hunt for you to walk all around the beautiful campus.

[college-tour.lac.tf](https://college-tour.lac.tf)

## Find the flag

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211120448.png)

***So, there are six hidden clues in the format `lactf{number_text}`.***

**View source page:**
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <title>A tour of UCLA</title>
    <link rel="stylesheet" href="index.css">
    <script src="script.js"></script>
</head>
<body>
    <h1>A tour of UCLA</h1>
    <button id="dark_mode_button" onclick="dark_mode()">Click me for Light Mode!</button>
    <p> After finally setting foot on UCLA's campus, you're excited to explore it. However, the new student advisors have hidden <b>six</b> clues in the format lactf{number_text} all across UCLA. To complete the scavenger hunt, you must merge all the parts into one in order. For example, if you find the clues lactf{1_lOsT}, lactf{2__!N_b} (note the repeated underscore), and lactf{3_03LT3r}, the answer is lactf{lOsT_!N_b03LT3r}. Have fun exploring!</p>
    <!-- lactf{1_j03_4}-->
    <img src="royce.jpg" alt="lactf{2_nd_j0}" height="400px">
    <iframe src="lactf{4_n3_bR}.pdf" width="100%" height="500px">
    </iframe>
</body>
```

In here, we already found 3 clues.

- `lactf{1_j03_4}`
- `lactf{2_nd_j0}`
- `lactf{4_n3_bR}`

**Then, go to the `index.css` style sheet:**
```css
[...]
.secret {
    font-family: "lactf{3_S3phI}"
}
[...]
```

Found the third clue!

**After that, go to the `script.js` JavaScript file:**
```js
[...]
else {
        document.getElementById("dark_mode_button").textContent = "Click me for lactf{6_AY_hi} Mode!";
    }
}

window.addEventListener("load", (event) => {
    document.cookie = "cookie=lactf{5_U1n_s}";
});
[...]
```

Found the fifth and sixth one!

**Finally, combine all clues together to get the real flag!!**

- **Flag: `lactf{j03_4nd_j0S3phIn3_bRU1n_sAY_hi}`**

# Conclusion

What we've learned:

1. Information Gathering Via View Source Page