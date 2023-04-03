# Rick Roll

- 53 Points / 343 Solves

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

I mean, do I need to say more?

[https://rickroll-web.challenges.ctf.ritsec.club/](https://rickroll-web.challenges.ctf.ritsec.club/)

NOTE: You will need to combine 5 parts of the flag together

NOTE: Each part of the flag is used only once

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401135113.png)

## Find the flag

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401135148.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401135154.png)

When we go to `/`, it'll redirect us to `/1.html`.

**Let's view the source page:**
```html
[...]
<link rel="stylesheet" href="2.css">
[...]
<a href="Don't.html" class="btn btn-rounded">Don't Sign In</a>
[...]
<!--
    FIND THE FLAGS
[...]
I just wanna tell you [_TuRna30unD_]how I'm feeling
[...]
-->
```

Nice rickroll.

And we found the first part of the flag!

- `_TuRna30unD_`

We can also see that in `/1.html` there's a CSS is loaded via `<link>` element: **`2.css`**

```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023)-[2023.04.01|13:53:12(HKT)]
└> curl https://rickroll-web.challenges.ctf.ritsec.club/2.css
[...]
Hey there you CTF solver, Good job on finding the actual challenge, so the task here is to find flags to complete the first half of the chorus of this song, and you
will find the flags around this entire web network in this format,/*[FLAG_PIECE]*/ Heres a piece to get started /*[RS{/\/eveRG0nna_]*/  find the next four parts of the famous chorus
[...]
.input button{
    [...]
    background-color: [_|3tY0|_|d0vvn] var(--primary-color);
    [...]
}
[...]
```

We found 2 more parts!

- `RS{/\/eveRG0nna_`
- `_|3tY0|_|d0vvn`

**Then, in `1.html`, we also see that there's a "Don't Sign In" link:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401140320.png)

**Again, view source page:**
```html
[...]
<link rel="stylesheet" href="1.css">
[...]
<!--
    Hi Again
[...]

    !It Might be here!
[...]
Your heart's been aching[_D3s3RTy0u}], but you're too shy to say it (to say it)
[...]
-->
```

Found the fourth one!

- `_D3s3RTy0u}`

**Next, we also see there's a `1.css` CSS file:**
```css
[...]
.btn{
    [...]
    border: /*[G1v3y0uuP]*/ none;
    [...]
}
[...]
.input button{
    [...]
    text-align: /*[_|3tY0|_|d0vvn_]*/center;
    [...]
}
```

Found the last part of the flag!

- `G1v3y0uuP`

**Hence, the full flag will be:**

- **Flag: `RS{/\/eveRG0nna_G1v3y0uuP_|3tY0|_|d0vvn_TuRna30unD__D3s3RTy0u}`**

## Conclusion

What we've learned:

1. Inspecting Source Pages