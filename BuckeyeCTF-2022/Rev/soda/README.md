# soda

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★★★★★★☆☆

> Man, I'm parched. I sure hope this vending machine doesn't suck...

```
nc pwn.chall.pwnoh.io 13375
```

> Author: gsemaj

> Difficulty: Beginner

## Find the flag

**In this challenge, we can download a file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221105040942.png)

```
┌──(root🌸siunam)-[~/ctf/BuckeyeCTF-2022/Rev/soda]
└─# file soda.jar 
soda.jar: Java archive data (JAR)
                                                                                                           
┌──(root🌸siunam)-[~/ctf/BuckeyeCTF-2022/Rev/soda]
└─# unzip soda.jar   
Archive:  soda.jar
   creating: META-INF/
  inflating: META-INF/MANIFEST.MF    
  inflating: soda$Drink$DrinkStatus.class  
  inflating: soda$Drink.class        
  inflating: soda$VendingMachine.class  
  inflating: soda.class
```

```
┌──(root🌸siunam)-[~/ctf/BuckeyeCTF-2022/Rev/soda]
└─# nc pwn.chall.pwnoh.io 13375

The prophecy states that worthy customers receive flags in their cans...

-------------------------------------------
| 1    | 2    | 3    | 4    | 5    | 6    |
|      |  __  |      |      |  __  |  __  |
|      | |  | |      |      | |  | | |  | |
|      | |__| |      |      | |__| | |__| |
|      |      |      |      |      |      |
| 0.89 | 5.58 | 2.46 | 0.92 | 2.24 | 0.23 |
-------------------------------------------
| 7    | 8    | 9    | 10   | 11   | 12   |
|  __  |  __  |  __  |  __  |      |  __  |
| |  | | |  | | |  | | |  | |      | |  | |
| |__| | |__| | |__| | |__| |      | |__| |
|      |      |      |      |      |      |
| 2.18 | 0.17 | 5.96 | 3.91 | 5.38 | 3.69 |
-------------------------------------------

I have $5.00 in my wallet
command> 
```

**Since we're dealing with Java application, I'll use JD-GUI to reverse engineering it!**
```
┌──(root🌸siunam)-[~/ctf/BuckeyeCTF-2022/Rev/soda]
└─# jd-gui
```

**In function `printFlag()`, we can see that it prints out the flag:**
```java
  private static void printFlag() {  
    try {  
      BufferedReader bufferedReader = new BufferedReader(new FileReader("flag.txt"));  
      System.out.println(">> WOAH!! There's a flag in here!!");  
      String str;  
      while ((str = bufferedReader.readLine()) != null)  
        System.out.println(str);   
    } catch (Exception exception) {  
      System.out.println(">> You find a piece of paper in the can! It reads:");  
      System.out.println("\n\t\"You are not worthy\"\n");  
    }   
  }
```

Function `retrieve()`:
```java
    public void retrieve() {  
      byte b = -1;  
      float f = -1.0F;  
      for (byte b1 = 0; b1 < 12; b1++) {  
        if ((this.drinks[b1]).status != soda.Drink.DrinkStatus.EMPTY &&   
          (this.drinks[b1]).cost > f) {  
          b = b1;  
          f = (this.drinks[b1]).cost;  
        }   
      }   
      if ((this.drinks[b]).status == soda.Drink.DrinkStatus.DROPPED) {  
        soda.printFlag();  
      } else {  
        System.out.println(">> No flags in here... was the prophecy a lie...?");  
      }   
    }
```

- If the drinks `status` is `dropped`, then run the `printFlag()` function

But how do we do other things?

**Well, in function `processCommand()`, we can see a lot of options:**
```java
  private static void processCommand(VendingMachine paramVendingMachine, String[] paramArrayOfString) {  
    if (paramArrayOfString[0].equalsIgnoreCase("help")) {  
      System.out.println(">> You're telling me you don't know how to use a vending machine?");  
      return;  
    }   
    if (paramArrayOfString[0].equalsIgnoreCase("purchase")) {  
      if (paramArrayOfString.length > 1)  
        try {  
          int i = Integer.parseInt(paramArrayOfString[1]);  
          if (i < 1 || i > 12)  
            throw new RuntimeException();   
          paramVendingMachine.buy(i - 1);  
          return;  
        } catch (Exception exception) {  
          System.out.println(">> That's not a real choice");  
          return;  
        }    
      System.out.println(">> Purchase what?");  
      return;  
    }   
    if (paramArrayOfString[0].equalsIgnoreCase("punch")) {  
      System.out.println(">> That's not a good idea");  
      return;  
    }   
    if (paramArrayOfString[0].equalsIgnoreCase("kick")) {  
      System.out.println(">> That's a terrible idea");  
      return;  
    }   
    if (paramArrayOfString[0].equalsIgnoreCase("shake")) {  
      System.out.println(">> That's the worst idea ever");  
      return;  
    }   
    if (paramArrayOfString[0].equalsIgnoreCase("shatter")) {  
      System.out.println(">> What is wrong with you???");  
      return;  
    }   
    if (paramArrayOfString[0].equalsIgnoreCase("reach")) {  
      if (bystanders) {  
        System.out.println(">> I can't do that with people around!\n>> They'll think I'm stealing!");  
        return;  
      }   
      int i = paramVendingMachine.reach();  
      paramVendingMachine.dropped += i;  
      if (i > 0) {  
        System.out.println(">> Ok, here goes... gonna reach through the door and try to knock it down...");  
        pause(3);  
        System.out.println(">> !!! I heard something fall!");  
      } else {  
        System.out.println(">> There's nothing to reach for");  
      }   
      return;  
    }   
    if (paramArrayOfString[0].equalsIgnoreCase("wait")) {  
      int i = 0;  
      try {  
        i = Integer.parseInt(paramArrayOfString[1]);  
      } catch (Exception exception) {  
        System.out.println(">> Not sure what you mean");  
        return;  
      }   
      pause(i);  
      if (i >= 10) {  
        bystanders = false;  
        System.out.println(">> ...Looks like nobody's around...");  
      } else {  
        bystanders = true;  
        System.out.println(">> People are walking down the street.");  
      }   
      return;  
    }   
    if (paramArrayOfString[0].equalsIgnoreCase("tap")) {  
      System.out.println(">> Tapping the glass is harmless, right?");  
      pause(1);  
      paramVendingMachine.tap();  
      System.out.println(">> Not sure if that helped at all...");  
      return;  
    }   
    if (paramArrayOfString[0].equalsIgnoreCase("grab")) {  
      if (paramVendingMachine.dropped > 0) {  
        System.out.println(">> Alright!! Let's see what I got!");  
        paramVendingMachine.retrieve();  
      } else {  
        System.out.println(">> There's nothing to grab...");  
      }   
      return;  
    }   
    System.out.println(">> Not sure what you mean");  
  }
```

**Let's break it down:**
- If we type `help`, it'll print: `>> You're telling me you don't know how to use a vending machine?`
- If we type `purchase <1-12>` and choose between 1 - 12, we'll buy a drink. Othewise print `>> That's not a real choice`. If we just type `purchase` and no 1 to 12 is supplied, prints `>> Purchase what?`
- If we type `punch`, it prints `>> That's not a good idea`
- If we type `kick`, it prints `>> That's a terrible idea`
- If we type `shake`, it prints `>> That's the worst idea ever`
- If we type `shatter`, it prints `>> What is wrong with you???`
- **If we type `reach`**, if `bystanders` is `True`, it prints `>> I can't do that with people around!\n>> They'll think I'm stealing!`. **If the `bystanders` is `False`, run function `reach()`, and `dropped` + `i`.**
- **If we type `wait`** and nothing else supplied, prints `>> Not sure what you mean`. If we supplied an integer in `wait`, we'll be paused for `i` second (Which is our input, `wait <i>`). **If `i` is greater or equals to 10, `bystanders` set to `True`**
- If we type `tap`, it prints `>> Tapping the glass is harmless, right?`, and wait 1 second, then prints `>> Not sure if that helped at all...`
- **If we type `grab`, if `dropped` greater than 0, run function `retrieve()`, which is prints out the flag**

Ok... Armed with above information, let's connect to the remote host and try!

**To do so, I'll:**

- Set `bystanders` to `False`:

```
┌──(root🌸siunam)-[~/ctf/BuckeyeCTF-2022/Rev/soda]
└─# nc pwn.chall.pwnoh.io 13375

The prophecy states that worthy customers receive flags in their cans...

-------------------------------------------
| 1    | 2    | 3    | 4    | 5    | 6    |
|  __  |  __  |  __  |      |      |  __  |
| |  | | |  | | |  | |      |      | |  | |
| |__| | |__| | |__| |      |      | |__| |
|      |      |      |      |      |      |
| 1.91 | 0.71 | 5.92 | 2.47 | 5.97 | 4.14 |
-------------------------------------------
| 7    | 8    | 9    | 10   | 11   | 12   |
|  __  |  __  |  __  |      |  __  |      |
| |  | | |  | | |  | |      | |  | |      |
| |__| | |__| | |__| |      | |__| |      |
|      |      |      |      |      |      |
| 2.31 | 5.77 | 5.97 | 3.72 | 4.52 | 5.01 |
-------------------------------------------

I have $5.00 in my wallet
command> wait 10
. . . . . . . . . . 
>> ...Looks like nobody's around...
```

- Purchase 1 item to set to status `stuck`:

```
command> purchase 1
>> [VENDING]
. . . . . 
>> ...Wait... IT'S STUCK?? NOOOOOO
```

- `tap` 3 times to set the `stuck` to greater than 0:

```
command> tap
>> Tapping the glass is harmless, right?
. 
>> Not sure if that helped at all...
[...]
command> tap
>> Tapping the glass is harmless, right?
. 
>> Not sure if that helped at all...
[...]
command> tap
>> Tapping the glass is harmless, right?
. 
>> Not sure if that helped at all...
[...]
```

- Set the status to `DROPPED` via `reach`:

```
command> reach
>> Ok, here goes... gonna reach through the door and try to knock it down...
. . . 
>> !!! I heard something fall!
```

In here, I tried to grab the flag, but no dice...

```
command> grab
>> Alright!! Let's see what I got!
>> No flags in here... was the prophecy a lie...?
```

And I stucked at here for a long time...

# Conclusion

What we've learned:

1. Reversing Java Application