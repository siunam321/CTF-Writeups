# open-source

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Find the Flag](#find-the-flag)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @siunam
- 106 solves / 100 points
- Difficulty: Easy
- Author: Sean
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

"open source" in the sense that if you open inspect element and go to the source tab all the source code is there!

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513162114.png)

## Enumeration

**Index page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513162131.png)

In here, we can submit a flag and the application will check whether the flag is correct or not in our browser console.

Let's try it!

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513162205.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513162221.png)

As expected, our testing flag is wrong.

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513162333.png)

By checking our HTTP history, the flag checking logic seems to be done on our **client-side**.

Hmm... I wonder how it works...

In our browser console, we can **view the source in the "Debugger"** by clicking the "`index.js:1`" link:

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513162509.png)

**Which pops up this JavaScript [source map](https://web.dev/articles/source-maps) file (`index.js.map`):**
```javascript
const form = document.getElementById('form')
form.onsubmit = () => {
  console.log('Checking flag...!')
  alert(
    document.querySelector('[name=flag]').value === 'ctf{this_is_not_the_flag}'
      ? 'true!! this is the FAKE flag'
      : 'false'
  )
}

console.log('Flag checker time!')

//
console.log(require('moment').__LIB_ID)
```

When the flag form is submitted, it'll check whether our flag's input field value is equals to `ctf{this_is_not_the_flag}` or not. If it is, pop up an alert box with text `true!! this is the FAKE flag`.

Uhh... So the flag form is just checking the **fake flag**?? Where's the real flag?

Also, in the last line of this source map file, it import the `moment` module on the **server-side** (`require`) and get the value of `__LIB_ID`??

In our "Debugger", we can also see there's another JavaScript file called **`index.js`**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513163223.png)

In here, we can see that the JavaScript code is **heavily obfuscated**.

**In the last bit of the obfuscated code, we can see this:**
```javascript
[...]var xS=P3;var PS={};var kS=()=>"a";var ES=()=>"c",OS=()=>"d";var M1=()=>"f",TS=()=>"g",CS=()=>"l",N3=()=>"n",A3=()=>"p",DS=()=>"s",RS=()=>"t",L3=()=>"e",MS={not:N3,particularly:A3,interesting:L3};console.log("Flag checker time!");what.addEventListener("submit",()=>{console.log("Checking flag...!"),alert(new FormData(what).get(M1()+CS()+kS()+TS())===[DS,OS,ES,RS,M1,()=>`{${Object.keys(MS).join("_")}}`].map(e=>e()).join("")?"true!! this is the real flag":"false")});console.log(`{${Object.keys({...r0,...I3,...F3,...PS,...U3,...W3,...R1}).join("}{")}}`.length);})();
```

Hmm? `true!! this is the real flag`?

So, it seems like the real flag checking logic is on this end.

Now, we can try to deobfuscate it via **online tools** or **manually**.

## Find the Flag

**First, we can go to [js-beautify](https://beautifier.io/) to clean the code:**
```javascript
var xS = P3;
var PS = {};
var kS = () => "a";

var ES = () => "c",
    OS = () => "d";
var M1 = () => "f",
    TS = () => "g",
    CS = () => "l",
    N3 = () => "n",
    A3 = () => "p",
    DS = () => "s",
    RS = () => "t",
    L3 = () => "e",
    MS = {
        not: N3,
        particularly: A3,
        interesting: L3
    };

console.log("Flag checker time!");

what.addEventListener("submit", () => {
    console.log("Checking flag...!")
    alert(new FormData(what).get(M1() + CS() + kS() + TS()) === [DS, OS, ES, RS, M1, () => `{${Object.keys(MS).join("_")}}`].map(e => e()).join("") ? "true!! this is the real flag" : "false")
});
console.log(`{${Object.keys({...r0,...I3,...F3,...PS,...U3,...W3,...R1}).join("}{")}}`.length);
})();
```

Much better now!

**Then, in the `submit` event listener, we can see that this `alert()` global function:**
```javascript
alert(new FormData(what).get(M1() + CS() + kS() + TS()) === [DS, OS, ES, RS, M1, () => `{${Object.keys(MS).join("_")}}`].map(e => e()).join("") ? "true!! this is the real flag" : "false")
```

**What it does is basically this:**
```javascript
let flagFormInputValue = new FormData(what).get("flag");
let realFlag = [DS, OS, ES, RS, M1, () => `{${Object.keys(MS).join("_")}}`].map(e => e()).join("");

if (flagFormInputValue === realFlag) {
    alert("true!! this is the real flag");
} else {
    alert("false");
}
```

**Hence, we can get the real flag by executing this:**
```javascript
var ES = () => "c",
    OS = () => "d";
var M1 = () => "f",
    TS = () => "g",
    CS = () => "l",
    N3 = () => "n",
    A3 = () => "p",
    DS = () => "s",
    RS = () => "t",
    L3 = () => "e",
    MS = {
        not: N3,
        particularly: A3,
        interesting: L3
    };

let realFlag = [DS, OS, ES, RS, M1, () => `{${Object.keys(MS).join("_")}}`].map(e => e()).join("");
console.log(realFlag);
```

```shell
┌[siunam♥Mercury]-(~/ctf/San-Diego-CTF-2024/Web/open-source)-[2024.05.13|16:53:12(HKT)]
└> nodejs       
[...]
> var ES = () => "c",
...     OS = () => "d";
undefined
> var M1 = () => "f",
...     TS = () => "g",
...     CS = () => "l",
...     N3 = () => "n",
...     A3 = () => "p",
...     DS = () => "s",
...     RS = () => "t",
...     L3 = () => "e",
...     MS = {
...         not: N3,
...         particularly: A3,
...         interesting: L3
...     };
undefined
> 
> let realFlag = [DS, OS, ES, RS, M1, () => `{${Object.keys(MS).join("_")}}`].map(e => e()).join("");
undefined
> console.log(realFlag);
sdctf{not_particularly_interesting}
undefined
```

Nice! We got the flag!

- **Flag: `sdctf{not_particularly_interesting}`**

## Conclusion

What we've learned:

1. Deobfuscate JavaScript code