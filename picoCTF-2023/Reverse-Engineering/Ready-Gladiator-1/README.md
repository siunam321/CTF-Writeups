# Ready Gladiator 1

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Author: LT 'syreal' Jones

Your opponent is the Imp. The source is available [here](https://artifacts.picoctf.net/c/408/imp.red). If you wanted to pit the Imp against himself, you could download the Imp and run your own core wars server

Description

Can you make a CoreWars warrior that wins? Your opponent is the Imp. The source is available [here](https://artifacts.picoctf.net/c/406/imp.red). If you wanted to pit the Imp against himself, you could download the Imp and connect to the CoreWars server like this: `nc saturn.picoctf.net 62467 < imp.red` To get the flag, you must beat the Imp at least once out of the many rounds.

## Find the flag

**In this challenge, we can `nc` to the instance machine:**
```shell
┌[siunam♥earth]-(~/ctf/picoCTF-2023/Reverse-Engineering/Ready-Gladiator-1)-[2023.03.28|22:54:49(HKT)]
└> nc saturn.picoctf.net 62467                   
Submit your warrior: (enter 'end' when done)


```

In here, we can submit our warrior.

**In this challenge, we can also download a file called `imp.red`:**
```asm
;redcode
;name Imp Ex
;assert 1
mov 0, 1
end
```

Hmm... First off, **what is "CoreWars"?**

**According to [Core Wars](https://www.corewars.org/) documentation:**

> **Core Wars** is a _programming game_ in which two or more programs run in a simulated computer with the goal of terminating every other program and surviving as long as possible. Known as _Warriors_, these programs are are written in an assembly language called _Redcode_.

Ahh, so the `imp.red` is written is "Redcode" assembly language.

**Then, I found the "[Core Wars for Dummies](https://www.corewars.org/docs/dummies.html)" in the documentation page:**

Introduction:

This document will attempt to explain Core Wars in general, so that the first time player may gain an understanding of Corewars and can begin to write Redcode.

My introduction to Core Wars was through Scientific American. Articles there described a game played in a virtual computer. Competing programs attempted to "kill" each other.

The programs were written in a language called Redcode. At first glance Redcode appears hard to decipher, but with a little bit of knowledge the programs yield up an abundance of information. That knowledge is written here.

Let's take a look at some basic concepts.

The Core:

The game of Core War is played in a virtual computer (called MARS <1>). While MARS can be any size, a common size is 8000 instructions. Programs are limited to a specific starting size, normally 100 instructions. Each program has a finite number of executions (turns, cycles), normally this number is 80,000. These parameters are the ones currently used by the 94 hill on the Pizza server. There can be any number of variations on other hills.

Instructions:

There are currently 17 instructions used in Redcode. This number has changed as the games has evolved. Each instruction has a three letter code (an example would the MOV for move.) They are listed below in no particular order.

```asm
DAT data
MOV move
ADD add
SUB subtract
MUL multiply
DIV divide
MOD modula (remainder of division)
JMP jump
JMZ jump if zero
JMN jump if not zero
DJN decrement, jump if not zero
SPL split execution
SLT skip if less than
CMP compare (see SEQ)
SEQ skip if equal
SNE skip if not equal
NOP no operation
```

Each instruction contains an "A" field and a "B" field. These fields tell MARS how to execute the instruction.

By example the MOV command simply tells the MARS to copy what is in the "A" field into the "B" field.

Chapter II

Bombing

In the previous chapter we learned the meaning of the 17 Opcodes. In this chapter we take a closer look at four of these instructions. These four are DAT, ADD, MOV, and JMP. To illustrate we will use a very simple program.

```asm
;redcode-94
;name Sleepy
;author John Q. Smith
;strategy bombing core

ADD #10, #-1
MOV 2, @-1
JMP -2, 0
DAT #33, #33

end
```

Let's see what that "Sleepy" warrior does!

- The `;redcode-94` tells the MARS know that this program is compliant with the proposed 1994 standard for Core Wars.
- The name (warrior) of this program is "Sleepy".

"Sleepy" attempts to destroy it's opponents by dropping the "`DAT #33, #33`" instruction in their path of operation. A process which attempts to execute a "DAT" statement dies.

Now that we know what it does, let's look at how it does it. The MOV command is really the cornerstone of this program. Without the move command the program has no punch. Let's see how it works.

```asm
MOV 2, @-1
Op A B
```

First off, notice that the "A" field points to the DAT statement. You can tell this by counting two from the MOV line. This means that the MOV statement will be coping the information at this location (the "DAT #33, #33").

The "B" field points to the line with the ADD statement in it. Ordinarily this would mean that the bomb would be copied on top of this statement, but the "@" symbol makes this an indirect pointer. In effect the "@" symbol says, use the "B" field I point to as a new location to point from. In this case the "B" field points to the location just before the ADD line (this location is not shown).

After the MOV statement is executed, the process goes to the next line. The JMP command indicates a location for the process to go to. Here the process jumps to the ADD command.

Now that we have bombed a location of core, we should change pointer to a new location so that we don't keep bombing the same place over and over. The ADD command changes the pointer by adding the number "#10" to it. The symbol "#" means that this is an immediate addressing mode. Put simply, this means deal with what is right here to complete you task.

```asm
ADD #10, #-1
Op A B
```

The add command adds the "A" field to the "B" field. Here both fields are in immediate mode, so the operation takes place on one line. After executing this instruction once, it would look as follows.

```asm
ADD #10, #9
Op A B
```

Now when the MOV command drops a DAT bomb, it will land nine lines below the ADD statement.

```asm
0 ADD #10, #9
1-> MOV 2, @-1
2 JMP -2, 0
3 DAT #33, #33
4
5
6
7
8
9 DAT #33, #33
```

Sleepy will continue to drop bombs into the core in ten line increments until the pointers rap around the core and return. At that point Sleepy begins to bomb over it's own bombs, doing to until the end of time (80,000 cycles) or until acted upon by another program.

Armed with above information, we can try to **win the "Imp" opponent via the "Sleepy" warrior!**

**But first, let's try the non-modified one:**
```shell
┌[siunam♥earth]-(~/ctf/picoCTF-2023/Reverse-Engineering/Ready-Gladiator-1)-[2023.03.28|23:05:08(HKT)]
└> nc saturn.picoctf.net 62467 < imp.red
;redcode
;name Imp Ex
;assert 1
mov 0, 1
end
Submit your warrior: (enter 'end' when done)

Warrior1:
;redcode
;name Imp Ex
;assert 1
mov 0, 1
end

Rounds: 100
Warrior 1 wins: 0
Warrior 2 wins: 0
Ties: 100
Try again. Your warrior (warrior 1) must win at least once.
```

As you can see, our warrior must win at least once.

**Let's use our "Sleepy" warrior!**
```asm
;redcode
;name Imp Ex
;assert 1
ADD #10, #-1
MOV 2, @-1
JMP -2, 0
DAT #33, #33
end
```

```
┌[siunam♥earth]-(~/ctf/picoCTF-2023/Reverse-Engineering/Ready-Gladiator-1)-[2023.03.28|23:05:10(HKT)]
└> nc saturn.picoctf.net 62467 < modified_imp.red 
;redcode
;name Imp Ex
;assert 1
ADD #10, #-1
MOV 2, @-1
JMP -2, 0
DAT #33, #33
end
Submit your warrior: (enter 'end' when done)

Warrior1:
;redcode
;name Imp Ex
;assert 1
ADD #10, #-1
MOV 2, @-1
JMP -2, 0
DAT #33, #33
end

Rounds: 100
Warrior 1 wins: 22
Warrior 2 wins: 0
Ties: 78
You did it!
picoCTF{1mp_1n_7h3_cr055h41r5_ec57a42e}
```

Nice! We successfully drops tons of DAT bomb, and we win the game!

- **Flag: `picoCTF{1mp_1n_7h3_cr055h41r5_ec57a42e}`**

## Conclusion

What we've learned:

1. Winning CoreWars "Imp"