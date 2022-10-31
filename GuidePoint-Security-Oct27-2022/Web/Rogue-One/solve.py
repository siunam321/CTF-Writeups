#!/usr/bin/env python3

import requests

url = 'http://10.10.100.200:38125/number/'

s = requests.Session()

r = s.get(url)
number = r.text

result = s.get(url + '?answer=' + number)
print(result.text)