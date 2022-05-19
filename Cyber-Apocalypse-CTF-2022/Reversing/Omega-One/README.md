# Background
![background1](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-CTF-2022/Reversing/Omega-One/images/background1.png)

![background2](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-CTF-2022/Reversing/Omega-One/images/background2.png)

# Solution

As usual, download the [downloadable file](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-CTF-2022/Reversing/Omega-One/rev_omega_one.zip) and unzip it.

After unzip that zip file, we see 2 files: `omega-one` and `output.txt`.

omega-one: 64-bit ELF executable

output.txt: A list of name??

![solution1](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-CTF-2022/Reversing/Omega-One/images/solution1.png)

![solution2](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-CTF-2022/Reversing/Omega-One/images/solution2.png)

Then we'll need to use any reverse engineering tools, like Ghidra.

In the `FUN_00100b4c` or main function, we see there are some weird strings, and **those strings matches the list of names in output.txt.**

![solution3](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-CTF-2022/Reversing/Omega-One/images/solution3.png)

Let's compare them one by one!!

```
Crerceon	--> H
Ezains		--> T
Ummuh		--> B
Zonnu		--> {
Vinzo		--> l
Cuzads		--> 1
Emoi		--> n
Ohols		--> 3
Groz'ens	--> 4
Ukox		--> r
Ehnu		--> _
Pheilons	--> t
Cuzads		--> 1
Khehlan		--> m
Ohols		--> 3
Ehnu		--> _
Munis		--> b
Inphas		--> u
Pheilons	--> t
Ehnu		--> _
Dut		--> p
Ukox		--> r
Ohols		--> 3
Pheilons	--> t
Pheilons	--> t
Zimil		--> y
Ehnu		--> _
Honzor		--> s
Vinzo		--> l
Ukteils		--> 0
Falnain		--> w
Dhohmu		--> !
Baadix		--> }
			|
			+-> HTB{l1n34r_t1m3_but_pr3tty_sl0w!}
```

![flag](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-CTF-2022/Reversing/Omega-One/images/flag.png)

And boom! Here you go!!

# Flag
`HTB{l1n34r_t1m3_but_pr3tty_sl0w!}`