# Red Team Activity

## Table of Contents

1. **[Red Team Activity 1](#red-team-activity-1)**
2. **[Red Team Activity 2](#red-team-activity-2)**
3. **[Red Team Activity 3](#red-team-activity-3)**
4. **[Red Team Activity 4](#red-team-activity-4)**

## Red Team Activity 1

- 84 Points / 199 Solves

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Q1: what was the script name that was dropped?

Note: Flag format is `RS{MD5sum(<answer string>)}`

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401175355.png)

## Find the flag

**In this challenge, we can download a file:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Forensics/Red-Team-Activity-1)-[2023.04.01|17:54:12(HKT)]
└> file auth.log 
auth.log: ASCII text, with very long lines (1096)
```

As you can see, it's the `auth.log`, which is a Linux log file that stores **system authorization information, including user logins and authentication machinsm that were used.**

**Since the challenge question is asking "script", we can search `.sh` files via `grep`:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Forensics/Red-Team-Activity-1)-[2023.04.01|17:55:28(HKT)]
└> grep '\.sh' auth.log
Mar 25 20:10:40 ctf-1 sudo:     root : (command continued) # sha256sum is installed by default in some other distros#012    elif check_exists sha256sum; then#012        SHA_COMMAND="sha256sum"#012    fi#012    if [[ "${SHA_COMMAND}" != "" ]]; then#012        log "Will use ${SHA_COMMAND} to validate the checksum of the downloaded file"#012        SHA_URL="${URL}.sha256"#012        SHA_PATH="${OUTPUT_PATH}.sha256"#012        ${CURL_COMMAND} -o "${SHA_PATH}" "${SHA_URL}"#012        if ${SHA_COMMAND} --status -c "${SHA_PATH}"; then#012            log "The downloaded file's checksum validated correctly"#012        else#012            SHA_EXPECTED=$(cat "${SHA_PATH}")#012            SHA_ACTUAL=$(${SHA_COMMAND} "${OUTPUT_PATH}")#012            if check_exists awk; then#012                SHA_EXPECTED=$(echo "${SHA_EXPECTED}" | awk '{print $1}')#012                SHA_ACTUAL=$(echo "${SHA_ACTUAL}" | awk '{print $1}')#012            fi#012            log_important "Checksum of the downloaded file did not validate correctly"#012           
Mar 25 20:49:58 ctf-1 snoopy[2515]: [login:ubuntu ssh:((undefined)) sid:2393 tty:/dev/pts/2 (0/root) uid:root(0)/root(0) cwd:/root/.ssh]: vim /dev/shm/_script2980.sh
[...]
```

Found it! The `_script2980.sh` script looks sussy!

**MD5 the answer:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Forensics/Red-Team-Activity-1)-[2023.04.01|17:54:13(HKT)]
└> echo -n '_script2980.sh' | md5sum                                                         
5d8b854103d79677b911a1a316284128  -
```

> Note: The `-n` flag is to ignore new line character at the end. Otherwise it'll generate a different MD5 hash.

- **Flag: `RS{5d8b854103d79677b911a1a316284128}`**

## Red Team Activity 2

- 90 Points / 161 Solves

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Q2: Name of the malicious service?

Note: Flag format is `RS{MD5sum(<answer string>)}`

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401175855.png)

## Find the flag

**In this challenge we can download a file:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Forensics/Red-Team-Activity-2)-[2023.04.01|17:59:09(HKT)]
└> file auth.log 
auth.log: ASCII text, with very long lines (1096)
```

As you can see, it's the `auth.log`, which is a Linux log file that stores **system authorization information, including user logins and authentication machinsm that were used.**

**Since the challenge's question is asking "service", we can use `grep` to find `.service` file:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Forensics/Red-Team-Activity-2)-[2023.04.01|18:03:05(HKT)]
└> grep '\.service' auth.log | grep 'systemctl enable'
Mar 25 20:10:40 ctf-1 sudo:     root : (command continued) launchd (after installing config)#012start_teleport_launchd() {#012    log "Starting Teleport via launchctl. It will automatically be started whenever the system reboots."#012    launchctl load ${LAUNCHD_CONFIG_PATH}/com.goteleport.teleport.plist#012    sleep ${ALIVE_CHECK_DELAY}#012}#012# start teleport via systemd (after installing unit)#012start_teleport_systemd() {#012    log "Starting Teleport via systemd. It will automatically be started whenever the system reboots."#012    systemctl enable teleport.service#012    systemctl start teleport.service#012    sleep ${ALIVE_CHECK_DELAY}#012}#012# checks whether teleport binaries exist on the host#012teleport_binaries_exist() {#012    for BINARY_NAME in teleport tctl tsh; do#012        if [ -f ${TELEPORT_BINARY_DIR}/${BINARY_NAME} ]; then return 0; else return 1; fi#012    done#012}#012# checks whether a teleport config exists on the host#012teleport_config_exists() { if [ -f ${TELEPORT_CONFIG_PATH} ]; then return 0; else return
Mar 25 20:51:39 ctf-1 snoopy[2530]: [login:ubuntu ssh:((undefined)) sid:2393 tty:/dev/pts/2 (0/root) uid:root(0)/root(0) cwd:/root/.ssh]: systemctl enable bluetoothd.service
```

Found it! The `bluetoothd.service` looks sussy!

**MD5 hash the answer:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Forensics/Red-Team-Activity-2)-[2023.04.01|17:59:10(HKT)]
└> echo -n 'bluetoothd.service' | md5sum
a9f8f8a0abe37193f5b136a0d9c3d869  -
```

> Note: The `-n` flag is to ignore new line character at the end. Otherwise it'll generate a different MD5 hash.

- Flag: `RS{a9f8f8a0abe37193f5b136a0d9c3d869}`

## Red Team Activity 3

- 193 Points / 96 Solves

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Q3: What is the location (the full path) responsible having run the malicious script repeatedly?

Note: Flag format is `RS{MD5sum(<answer string>)}`

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401181719.png)

## Find the flag

**In this challenge, we can download a file:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Forensics/Red-Team-Activity-3)-[2023.04.01|18:09:30(HKT)]
└> file auth.log 
auth.log: ASCII text, with very long lines (1096)
```

As you can see, it's the `auth.log`, which is a Linux log file that stores **system authorization information, including user logins and authentication machinsm that were used.**

In Red Team Activity 1, we found **the malicious script is `_script2980.sh` in `/dev/shm/`**.

Now, the challenge's question is asking "repeatedly". Which technique in red teaming is to repeatedly executing something?

You guessed! "***Persistence***"!

How to implement persistence in Linux? ***Cronjob***!

**With that said, let's see any cronjobs has been modified/added!**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Forensics/Red-Team-Activity-3)-[2023.04.01|18:15:10(HKT)]
└> grep 'crontabs' auth.log                           
Mar 25 20:56:56 ctf-1 snoopy[14959]: [login:ubuntu ssh:((undefined)) sid:14897 tty:/dev/pts/3 (0/root) uid:root(0)/root(0) cwd:/root]: vim /var/spool/cron/crontabs/root
```

Found it! `/var/spool/cron/crontabs/root` is the new cronjob!

**MD5 hash the answer:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Forensics/Red-Team-Activity-3)-[2023.04.01|18:10:48(HKT)]
└> echo -n '/var/spool/cron/crontabs/root' | md5sum
c1da8fd57f17c95c731c38ee630f6aea  -
```

- **Flag: `RS{c1da8fd57f17c95c731c38ee630f6aea}`**

## Red Team Activity 4

- 381 Points / 109 Solves

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Q4: Which binary (full path to binary) was _**modified**_ by redteam to _**later**_ escalate privileges?

Note: Flag format is `RS{MD5sum(<answer string>)}`

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401181729.png)

## Find the flag

**In this challenge, we can download a file:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Forensics/Red-Team-Activity-4)-[2023.04.01|18:17:58(HKT)]
└> file auth.log 
auth.log: ASCII text, with very long lines (1096)
```

As you can see, it's the `auth.log`, which is a Linux log file that stores **system authorization information, including user logins and authentication machinsm that were used.**

Since the challenge's question is asking for privilege escalation, we can try to find common privilege escalation techniques, like SUID binary, sudo permission, writeable `/etc/passwd` and more.

**After some searching, I found this:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Forensics/Red-Team-Activity-4)-[2023.04.01|18:20:13(HKT)]
└> grep 'chmod' auth.log   
[...]
Mar 25 21:15:32 ctf-1 snoopy[15105]: [login:ubuntu ssh:((undefined)) sid:14897 tty:/dev/pts/3 (0/root) uid:root(0)/root(0) cwd:/root]: chmod u+s /usr/bin/find
[...]
```

In here, ***the `/usr/bin/find` has added the SUID sticky bit***, and user can execute the binary as the owner. In this case, it's root.

**MD5 hash the answer:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Forensics/Red-Team-Activity-4)-[2023.04.01|18:20:29(HKT)]
└> echo -n '/usr/bin/find' | md5sum
7fd5884f493f4aaf96abee286ee04120  -
```

- **Flag: `RS{7fd5884f493f4aaf96abee286ee04120}`**

## Conclusion

What we've learned:

1. Analysing Post-Exploitation Activity