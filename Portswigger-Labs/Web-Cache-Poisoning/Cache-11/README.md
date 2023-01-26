# Combining web cache poisoning vulnerabilities

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-combining-vulnerabilities), you'll learn: Combining web cache poisoning vulnerabilities! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★★☆☆☆☆

## Background

This lab is susceptible to [web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning), but only if you construct a complex exploit chain.

A user visits the home page roughly once a minute and their language is set to English. To solve this lab, poison the cache with a response that executes `alert(document.cookie)` in the visitor's browser.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-11/images/Pasted%20image%2020230126163414.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-11/images/Pasted%20image%2020230126163430.png)

As you can see, it has an `X-Cache` response header, which means the web application is using web cache.

**View source page:**
```html
[...]
<script>
    data = {
        "host":"0a3900fd04cc1f54c0439a2c008e00af.web-security-academy.net",
        "path":"/",
    }
</script>
[...]
<form>
    <select id=lang-select onchange="((ev) => { ev.currentTarget.parentNode.action = '/setlang/' + ev.target.value; ev.currentTarget.parentNode.submit(); })(event)">
    </select>
</form>
[...]
<script type="text/javascript" src="\resources\js\translations.js"></script>
[...]
<script>
    initTranslations('//' + data.host + '/resources/json/translations.json');
</script>
```

**In the `<select>` element, it has an event called `onchange`:**

- When the `<select>` element is changed, send a GET request to `/setlang/<selected_language>`.

**Let's send that request to Burp Suite's Repeater, and change the selected language value:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-11/images/Pasted%20image%2020230126164801.png)

As you can see, **it'll set a new cookie called `lang`, and value is our supplied language!**

**Also, the website loaded a JavaScript called `translations.js`:**
```js
function initTranslations(jsonUrl)
{
    const lang = document.cookie.split(';')
        .map(c => c.trim().split('='))
        .filter(p => p[0] === 'lang')
        .map(p => p[1])
        .find(() => true);

    const translate = (dict, el) => {
        for (const k in dict) {
            if (el.innerHTML === k) {
                el.innerHTML = dict[k];
            } else {
                el.childNodes.forEach(el_ => translate(dict, el_));
            }
        }
    }

    fetch(jsonUrl)
        .then(r => r.json())
        .then(j => {
            const select = document.getElementById('lang-select');
            if (select) {
                for (const code in j) {
                    const name = j[code].name;
                    const el = document.createElement("option");
                    el.setAttribute("value", code);
                    el.innerText = name;
                    select.appendChild(el);
                    if (code === lang) {
                        select.selectedIndex = select.childElementCount - 1;
                    }
                }
            }

            lang in j && lang.toLowerCase() !== 'en' && j[lang].translations && translate(j[lang].translations, document.getElementsByClassName('maincontainer')[0]);
        });
}
```

It also ran a JavaScript function called `initTranslations()`, which parses the `data.host`'s `/resources/json/translations.json`.

**`translations.json`:**
```json
{
    "en": {
        "name": "English"
    },
    "es": {
        "name": "español",
        "translations": {
            "Return to list": "Volver a la lista",
            "View details": "Ver detailes",
            "Description:": "Descripción:"
        }
    },
    "cn": {
        "name": "中文",
        "translations": {
            "Return to list": "返回清單",
            "View details": "查看詳情",
            "Description:": "描述:"
        }
    },
    "ar": {
        "name": "عربى",
        "translations": {
            "Return to list": "العودة إلى القائمة",
            "View details": "عرض التفاصيل",
            "Description:": "وصف:"
        }
    },
    "en-gb": {
        "name": "Proper English",
        "translations": {
            "Return to list": "From whence you came",
            "View details": "Do me the honour of elaborating",
            "Description:": "Pontifications on the subject matter:"
        }
    },
    "ml": {
        "name": "മലയാളം",
        "translations": {
            "Return to list": "ലിസ്റ്റിലേക്ക് മടങ്ങുക",
            "View details": "വിശദാംശങ്ങൾ കാണുക",
            "Description:": "വിവരണം:"
        }
    },
    "hb": {
        "name": "עברית",
        "translations": {
            "Return to list": "חזור לרשימה",
            "View details": "הצג פרטים",
            "Description:": "תיאור:"
        }
    },
    "zl": {
        "name": "Ẕ̻͕̿̊ͤ̍ͅa͙l̗ͧg̮̤̰̘͇ȍ͇͕̳̙͙͉́̅̋̌̅",
        "translations": {
            "Return to list": "Re̹̰̘͉̹̪ͅt̬̫̜ȕͩ͒ͥͥr̃̉͒n ̎͂t͎͖̽͋o͖̟͚͙̲͐ͤͫ̎̓ ̼̟͈̭͉͎̂ͯ̔ͤͤ̏͐ͅliͤ͑ͧ̆̐̈̀sṭ̠̮̰͍̙͒̔͆̈ͤ̅",
            "View details": "V̖̮͙ͅi͇e͙̦w̭̣̫͇̦̬̰ ̓͑̓ͯ̔d͍͂e͚̮͖͍͖̠͙ͮͭ̉ͦ̏͌̆t̙͎̺͉a̳̖͔̱͉̱͑̆̌̃͊ͬi̯͚͙̼̹̮l̖͎͛̈́͒ͅs̒̒ͤ̽̒̀",
            "Description:": "D̳͔e̝ͩ̐ͅsc̗̱̼̤̬̎̓ͪͣͭ̐ͅr̪̝͖̙̱̄̓͌̓̚ip̭̦̭̰̻ͣ̓̽ͨ̚ț̤̝̻i̹̱̟̞͕̓̓ͬ̓ͬ̆ͅon̠͚͕̈́̋̓:"
        }
    },
    "fn": {
        "name": "Suomalainen",
        "translations": {
            "Return to list": "Palaa luetteloon",
            "View details": "Näytä kuvaus",
            "Description:": "Kuvaus:"
        }
    },
    "hw": {
        "name": "Ōlelo Hawaiʻi",
        "translations": {
            "Return to list": "Hoʻi i ka papa inoa",
            "View details": "E nānā i nā kikoʻī",
            "Description:": "ʻO keʻano:"
        }
    },
    "mm": {
        "name": "ဗမာ",
        "translations": {
            "Return to list": "စာရင်းသို့ပြန်သွားသည်",
            "View details": "အသေးစိတ်ကြည့်ရန်",
            "Description:": "ဖော်ပြချက်:"
        }
    }
}
```

Let's break `translations.js` down!

**When the `initTranslations()` function is called, it'll:**

- Find the `lang` cookie's language value
- Send a GET request to `translations.json` and fetch it's content
- Then, create an element `<option>`, set it's attribute `value` to our cookie's language value
- After that, use `innerText` to append the language's name. For example, "English"
- **If the language's value is NOT `en`, change the `maincontainer` text to supplied language via `innerHTML` sink (Dangerous function)**

**After translated, it'll append a GET parameter `localized`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-11/images/Pasted%20image%2020230126170244.png)

Armed with above information, **we can try to exploit DOM-based XSS via the `innerHTML` sink in `translations.js`!**

But first, we need to find the source (Attacker's controlled input).

**In the view source page, we found this:**
```html
<script>
    data = {
        "host":"0a3900fd04cc1f54c0439a2c008e00af.web-security-academy.net",
        "path":"/",
    }
</script>
```

**If we can control the `data.host` value**, we can basically load any JSON file from anywhere!

**The evil JSON file can contain an XSS payload:**
```json
    "es": {
        "name": "español",
        "translations": {
            "Return to list": "Volver a la lista",
            "View details": "</a><img src=errorpls onerror=alert(document.domain)>",
            "Description:": "Descripción:"
        }
    },
```

After it fetches our evil JSON file, **it'll append our XSS payload to the `el.innerText` in the `translations.js`** JavaScript file, which will then trigger our XSS payload!!

**After some trial and error, I found that the web application accept `X-Forwarded-Host` HTTP header!!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-11/images/Pasted%20image%2020230126170627.png)

> Note: I'm providing a random GET parameter to prevent affecting the real users. This is so call "cache buster".

That being said, we can override the `data.host` value!!

**We now can go to exploit server, and host our evil JSON file!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-11/images/Pasted%20image%2020230126172517.png)

Then, intercept the `/?buster=buster1` GET request, and add the `X-Forwarded-Host` HTTP header with the exploit server domain:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-11/images/Pasted%20image%2020230126170935.png)

Forward the request:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-11/images/Pasted%20image%2020230126170959.png)

Our evil JSON file didn't loaded because of the CORS (Cross-Origin Resource Sharing) Policy...

**Luckly, we can add a HTTP header called `Access-Control-Allow-Origin`!**

**That being said, go back to the exploit server, and add a HTTP header:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-11/images/Pasted%20image%2020230126172542.png)

**Intercept the request again:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-11/images/Pasted%20image%2020230126172805.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-11/images/Pasted%20image%2020230126172817.png)

Hmm... Our language is set to "English".

**To fix that, we can add `lang` cookie with value `es`, and poison the cache:** 

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-11/images/Pasted%20image%2020230126173333.png)

Boom! We successfully triggered our XSS payload!

**We can also poison the `?localized=1` cache:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-11/images/Pasted%20image%2020230126173551.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-11/images/Pasted%20image%2020230126173619.png)

When the victim changed his/her language to `es`, it'll triggered an XSS payload.

However, in the lab's background, **the victim is setting his/her language to English... Which couldn't trigger our XSS payload!**

After poking around in the Burp Suite HTTP history, I found this:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-11/images/Pasted%20image%2020230126174459.png)

When we change to any language, it'll redirect us to `/setlang/<selected_language>`.

What if we can poison the path, and redirect to our XSS payload?

After some trial and error, I found that we can add a HTTP header called `X-Original-URL`. This header allows us to change the path of the request!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-11/images/Pasted%20image%2020230126174948.png)

However, the request can't be poison because it contains the `Set-Cookie` header...

Luckly, we can bypass that!

**In the home page, I found that the import of the `translations.js` JavaScript file is weird:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-11/images/Pasted%20image%2020230126175231.png)

As you can see, it's using backslashes (`\`) as a folder separator.

So, looks like the web server normalizes those backslashes to forward slashes using a redirect.

**Armed with above information, we can use backslash in our `X-Original-URL` header!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-11/images/Pasted%20image%2020230126175550.png)

And it's cacheable!!

Now, we can **poison the `/` to trigger a redirect to set our specified language**, which will then trigger our XSS payload from poisoned specified language cache!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-11/images/Pasted%20image%2020230126175925.png)

When the victim visit `/`, it'll force them to change our specified language!!

Let's summarize the exploit chain!

1. Poison the `/` to redirect victim to `/setlang\es`, which force them to set our specified language
2. Poison the `/?localized=1` to our evil JSON file, which then trigger our XSS payload when the language is `es`

Let's do that!!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-11/images/Pasted%20image%2020230126183215.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-11/images/Pasted%20image%2020230126183227.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-11/images/Pasted%20image%2020230126183232.png)

Nice!

> Note: If you couldn't solve the lab, you could try to change the payload's `alert()` function from `document.domain` to `document.cookie`, as I forgot to do so.

# What we've learned:

1. Combining web cache poisoning vulnerabilities