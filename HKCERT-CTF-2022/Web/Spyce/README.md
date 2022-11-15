# Spyce

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

- Challenge difficulty: ★☆☆☆☆

## Background

Flag 1: Read `/flag1`

Web: [http://chal-a.hkcert22.pwnable.hk:28039](http://chal-a.hkcert22.pwnable.hk:28039) , [http://chal-b.hkcert22.pwnable.hk:28039](http://chal-b.hkcert22.pwnable.hk:28039)

Attachment: [spyce_222c677640e7721636b146c58425aee3.zip](https://file.hkcert22.pwnable.hk/spyce_222c677640e7721636b146c58425aee3.zip)

Solution: [https://hackmd.io/@blackb6a/hkcert-ctf-2022-i-en-3f8a9ef6](https://hackmd.io/@blackb6a/hkcert-ctf-2022-i-en-3f8a9ef6)

## Find the flag

**In this challenge, we can download an attachment:**
```
┌──(root🌸siunam)-[~/ctf/HKCERT-CTF-2022/Web/Spyce]
└─# unzip spyce_222c677640e7721636b146c58425aee3.zip 
Archive:  spyce_222c677640e7721636b146c58425aee3.zip
  inflating: Dockerfile
```

**`Dockerfile`:**
```
FROM python:2.7.18-buster

COPY flag1 /flag1
COPY flag2 /flag2
RUN mv /flag2 /flag2-$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 64 | head -n 1)
RUN chown root /flag* && chmod 444 /flag*

RUN pip install SQLAlchemy pysqlite
RUN apt-get -y update && apt-get install -y sqlite cron

RUN useradd spwnce --create-home
USER spwnce 
WORKDIR /home/spwnce

COPY spyce-2.1-3.zip /tmp
RUN unzip /tmp/spyce-2.1-3.zip -d /tmp

# fix the reserved word 'as' and 'with'
COPY --chown=spwnce:spwnce spyce.py /tmp/spyce-2.1/spyce.py     
COPY --chown=spwnce:spwnce form.py /tmp/spyce-2.1/tags/form.py 

RUN cp -R /tmp/spyce-2.1/* /home/spwnce/

# backup and recovery
USER root
RUN mv /tmp/spyce-2.1/* /root/
RUN crontab -l | { cat; echo "*/1 * * * * cp -Rp /root/* /home/spwnce"; } | crontab
COPY entrypoint.sh /entrypoint.sh
RUN chmod 555 /entrypoint.sh

CMD ["/entrypoint.sh"]
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221111054040.png)

**chal-a:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221111054218.png)

**`Spyce 2.1.3`? Let's look at are there any public exploits via `searchsploit`:**
```
┌──(root🌸siunam)-[~/ctf/HKCERT-CTF-2022/Web/Spyce]
└─# searchsploit Spyce 2.1.3
-------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                          |  Path
-------------------------------------------------------------------------------------------------------- ---------------------------------
Spyce 2.1.3 - '/docs/examples/redirect.spy' Multiple Cross-Site Scripting Vulnerabilities               | php/webapps/31265.txt
Spyce 2.1.3 - '/spyce/examples/formtag.spy' Multiple Cross-Site Scripting Vulnerabilities               | php/webapps/31269.txt
Spyce 2.1.3 - 'docs/examples/handlervalidate.spy?x' Cross-Site Scripting                                | php/webapps/31266.txt
Spyce 2.1.3 - 'spyce/examples/getpost.spy?Name' Cross-Site Scripting                                    | php/webapps/31268.txt
Spyce 2.1.3 - 'spyce/examples/request.spy?name' Cross-Site Scripting                                    | php/webapps/31267.txt
Spyce 2.1.3 - spyce/examples/automaton.spy Direct Request Error Message Information Disclosure          | php/webapps/31270.txt
-------------------------------------------------------------------------------------------------------- ---------------------------------
```

Some XSS exploits? That's not helpful, as I don't see any account that I can hijack.

**Hmm... Let's poking around the web page!**

**Let's click on `Hello, world`!** 

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221111054639.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221111054821.png)

**In here, we can there is a `Source for this page`! Which would be helpful for us!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221111054905.png)

**Hmm... Looks like the `path` GET parameter might vulnerable to Local File Inclusion (LFI)!**

```
%2Fhome%2Fspwnce%2Fwww%2Fdocs%2Fexamples%2Fhello.spy
```

**Which in URL decoded:**
```
/home/spwnce/www/docs/examples/hello.spy
```

**Armed with this information, we can just get the flag!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221111055157.png)

We got the flag!

# Conclusion

What we've learned:

1. Local File Inclusion (LFI)