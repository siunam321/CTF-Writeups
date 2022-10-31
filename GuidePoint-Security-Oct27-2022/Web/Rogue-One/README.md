# Rogue One

## Overview

- Overall difficulty for me: Very easy

**In this challenge, we can start a docker instance:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221028063644.png)

## Find the flag

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221028063716.png)

**When we click the `Begin here`, it'll generate a random string:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221028063801.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221028063926.png)

**Too slow... Alright then, I'll write a [python script](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/Web/Rogue-One/solve.py) to solve this:**
```py
#!/usr/bin/env python3

import requests

url = 'http://10.10.100.200:38125/number/'

s = requests.Session()

r = s.get(url)
number = r.text

result = s.get(url + '?answer=' + number)
print(result.text)
```

**Output:**
```
┌──(root🌸siunam)-[~/ctf/GuidePoint-Security-Oct27-2022/Web/Rogue-One]
└─# python3 solve.py
GPSCTF{2692edb3426f224b78d695938de352e3}
```

We got the flag!

# Conclusion

What we've learned:

1. Sending GET Requests in Python