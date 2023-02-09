# JVM Reverse Engineering

## Introduction

Welcome to my another writeup! In this TryHackMe [JVM Reverse Engineering](https://tryhackme.com/room/jvmreverseengineering) room, you'll learn: Java bytecode reverse engineering and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★★★★☆☆

## Table of Content

1. **[Task 1 - Introduction](#task-1--introduction)**
2. **[Task 2 - Simple Hello World](#task-2--simple-hello-world)**
3. **[Task 3 - Cracking a password protected application](#task-3--cracking-a-password-protected-application)**
4. **[Task 4 - Basic String Obfuscation](#task-4--basic-string-obfuscation)**
5. **[Task 5 - Advanced bytecode manipulation](#task-5--advanced-bytecode-manipulation)**
6. **[Task 6 - Advanced String Obfuscation](#task-6--advanced-string-obfuscation)**
7. **[Task 7 - Extreme Obf](#task-1--extreme-obf)**

## Background

> Learn Reverse Engineering for Java Virtual Machine bytecode
>  
> Difficulty: Medium

---

## Task 1 - Introduction

When java applications are compiled, they are turned into an intermediary form of machine code, known as bytecode. While java source code is designed to be easy for humans to read, bytecode is designed to be easy for machines to read.

When you execute a compiled java application the class file is read and interpreted by a Java Virtual Machine. This is like a custom virtual CPU that runs inside your existing CPU and follows a different instruction set, the JVM instruction set.

Java Bytecode is a stack based language. This means that temporary variables are stored in the stack, rather than how x86 stores in registers. Stacks are like buckets. When you add a variable to the stack, you put it at the top of the bucket. When you remove/use a variable from the stack you use the variable at the top of the stack. If you attempt to retrieve a variable from an empty stack this is known as a Stack Underflow. If you add too many variables such that the stack reaches its memory limit, this is known as a Stack Overflow (Think of a bucket overflowing from too many items).

The java bytecode to print "Hello World" to console is shown below:

```java
getstatic java/lang/System.out:Ljava/io/PrintStream; // Retrieve the static variable "out" in the System class and store it on the stack
```


```java
ldc "Hello World" // Load the string "Hello World" onto the stack
```

```java
invokevirtual java/io/PrintStream.println:(Ljava/lang/String;)V // Invoke the "println" function on the System.out variable using the string at the top of the stack as an argument
```

For more information on the JVM instruction set I highly recommend [https://en.wikipedia.org/wiki/Java_bytecode_instruction_listings](https://en.wikipedia.org/wiki/Java_bytecode_instruction_listings).

Because JVM Bytecode is a high level representation of the original source code, constructs such as methods, fields and classes are still visible.

Classes are compiled into .class files, one class per file. These can reference other classes which will be linked by the JVM at runtime. By using a parser such as javap we are able to see the methods and fields present in a class. Each will have a name and a descriptor. The descriptor is a representation of the arguments and return type a method can take, or the type of a field.

The following method:

```java
void main(String[] args, int i)
```

would produce this descriptor and name:

```java
main([Ljava/lang/String;I)V
```

The args are surrounded in brackets. A `[` brace represents an array. An object is represented by a fully qualified internal name prepended by an `L` and appended by an `;`. The `I` represents an Int, and the `V` at the end represents the type void. A full writeup on descriptors can be seen here: [https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.3](https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.3).

Javap is a tool bundled with JDK releases that can disassemble compiled classes. Example usage:

(p = show private members, v = verbose)

```shell
javap -v -p HelloWorld.class
```

### Question 1 - Which value is now at the top of the stack?

Consider the following bytecode:

```java
LDC 0
LDC 3
SWAP
POP
INEG
```

According to [JVM intruction set](https://en.wikipedia.org/wiki/List_of_Java_bytecode_instructions), we can find the value:

- LDC: Push a constant `#index` from a constant pool (String, int, float, Class, java.lang.invoke.MethodType, java.lang.invoke.MethodHandle, or a dynamically-computed constant) onto the stack
- SWAP: Swaps two top words on the stack (note that value1 and value2 must not be double or long)
- POP: Discard the top value on the stack
- INEG: Negate int

Armed with above information, we can put all the puzzles together:

- LDC 0:

**Push an integer `0` onto the stack.**

Stack: Integer `0`

- LDC 3:

**Push an integer `3` onto the stack.**

Stack: Integer `03`

- SWAP:

**Swaps `0` and `3` top words on the stack.**

Stack: Integer `30`

- POP:

**Discard `0` on the stack.**

Stack: Integer `3`

- INEG:

Negate integer: `-3`

Stack: Integer `-3`

- **Answer: `-3`**

### Question 2 - Which opcode is used to get the XOR of two longs? (answer in lowercase)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/JVM-Reverse-Engineering/images/Pasted%20image%2020230129151055.png)

- **Answer: `lxor`**

### Question 3 - What does the -v flag on javap stand for? (answer in lowercase)

- **Answer: `verbose`**

## Task 2 - Simple Hello World

Complete the follow challenges.

---

**In this task, we can download a file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/JVM-Reverse-Engineering/images/Pasted%20image%2020230129151142.png)

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task2)-[2023.01.29|15:01:42(HKT)]
└> file Main.class 
Main.class: compiled Java class data, version 52.0 (Java 1.8)
```

### Question 1 - Find the name of the file that this class was compiled from (AKA Source File)

**To find it, we can use `javap`:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task2)-[2023.01.29|15:01:20(HKT)]
└> javap -v -p Main.class
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Classfile /home/siunam/ctf/thm/ctf/JVM-Reverse-Engineering/Task2/Main.class
  Last modified Jan 29, 2023; size 438 bytes
  SHA-256 checksum 0cbf8b75eb0083b8929cd20b5544791be35321ec707655fa036b149be55a49cd
  Compiled from "SecretSourceFile.java"
class Main
[...]
```

- **Answer: `SecretSourceFile.java`**

### Question 2 - What is the super class of the Main class? (Using internal name format, i.e. /)

**Again, `javap` can help us:**
```shell
[...]
class Main
  minor version: 0
  major version: 52
  flags: (0x0020) ACC_SUPER
  this_class: #5                          // Main
  super_class: #6                         // java/lang/Object
[...]
```

- **Answer: `java/lang/Object`**

### Question 3 - What is the value of the local variable in slot 1 when the method returns? (In decimal format)

**In `javap`'s output, we see all instructions:**
```java
public static void main(java.lang.String[]);
descriptor: ([Ljava/lang/String;)V
flags: (0x0009) ACC_PUBLIC, ACC_STATIC
Code:
  stack=2, locals=2, args_size=1
     0: iconst_0
     1: istore_1
     2: getstatic     #2                  // Field java/lang/System.out:Ljava/io/PrintStream;
     5: ldc           #3                  // String Hello World
     7: invokevirtual #4                  // Method java/io/PrintStream.println:(Ljava/lang/String;)V
    10: iinc          1, 2
    13: return
  LineNumberTable:
    line 5: 0
    line 6: 2
    line 7: 10
    line 8: 13
```

As you can see, the `locals` is equals to `2`.

- **Answer: `2`**

## Task 3 - Cracking a password protected application

The given class file takes a password as a parameter. You need to find the correct one. Tools like javap will be sufficient.

---

### Question 1 - What is the correct password

**In this task, we can download a file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/JVM-Reverse-Engineering/images/Pasted%20image%2020230203192646.png)

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task3)-[2023.02.03|19:27:03(HKT)]
└> file PasswordProtectedApplication.class 
PasswordProtectedApplication.class: compiled Java class data, version 52.0 (Java 1.8)
```

In this task's description, the `class` file takes a password as a parameter.

**We can use `java` to run that file:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task3)-[2023.02.03|19:27:36(HKT)]
└> java PasswordProtectedApplication test    
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
You guessed the wrong password
```

When we supplied an incorrect password, it outputs "You guessed the wrong password".

**Now, we can use `javap` to reverse engineer that compiled Java `class` file:**
```java
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task3)-[2023.02.03|19:27:38(HKT)]
└> javap -v -p PasswordProtectedApplication 
[...]
public class PasswordProtectedApplication
  minor version: 0
  major version: 52
  flags: (0x0021) ACC_PUBLIC, ACC_SUPER
  this_class: #9                          // PasswordProtectedApplication
  super_class: #10                        // java/lang/Object
  interfaces: 0, fields: 0, methods: 2, attributes: 1
Constant pool:
   #1 = Methodref          #10.#21        // java/lang/Object."<init>":()V
   #2 = String             #22            // {Redacted}
   #3 = Methodref          #23.#24        // java/lang/String.equals:(Ljava/lang/Object;)Z
   #4 = Fieldref           #25.#26        // java/lang/System.out:Ljava/io/PrintStream;
   #5 = String             #27            // You guessed the correct password
   #6 = Methodref          #28.#29        // java/io/PrintStream.println:(Ljava/lang/String;)V
   #7 = String             #30            // You guessed the wrong password
   #8 = String             #31            // Please supply a password
   #9 = Class              #32            // PasswordProtectedApplication
  #10 = Class              #33            // java/lang/Object
  #11 = Utf8               <init>
  #12 = Utf8               ()V
  #13 = Utf8               Code
  #14 = Utf8               LineNumberTable
  #15 = Utf8               main
  #16 = Utf8               ([Ljava/lang/String;)V
  #17 = Utf8               StackMapTable
  #18 = Class              #34            // java/lang/String
  #19 = Utf8               SourceFile
  #20 = Utf8               PasswordProtectedApplication.java
  #21 = NameAndType        #11:#12        // "<init>":()V
  #22 = Utf8               {Redacted}
  #23 = Class              #34            // java/lang/String
  #24 = NameAndType        #35:#36        // equals:(Ljava/lang/Object;)Z
  #25 = Class              #37            // java/lang/System
  #26 = NameAndType        #38:#39        // out:Ljava/io/PrintStream;
  #27 = Utf8               You guessed the correct password
  #28 = Class              #40            // java/io/PrintStream
  #29 = NameAndType        #41:#42        // println:(Ljava/lang/String;)V
  #30 = Utf8               You guessed the wrong password
  #31 = Utf8               Please supply a password
  #32 = Utf8               PasswordProtectedApplication
  #33 = Utf8               java/lang/Object
  #34 = Utf8               java/lang/String
  #35 = Utf8               equals
  #36 = Utf8               (Ljava/lang/Object;)Z
  #37 = Utf8               java/lang/System
  #38 = Utf8               out
  #39 = Utf8               Ljava/io/PrintStream;
  #40 = Utf8               java/io/PrintStream
  #41 = Utf8               println
  #42 = Utf8               (Ljava/lang/String;)V
[...]
```

```java
public PasswordProtectedApplication();
descriptor: ()V
flags: (0x0001) ACC_PUBLIC
Code:
  stack=1, locals=1, args_size=1
     0: aload_0
     1: invokespecial #1                  // Method java/lang/Object."<init>":()V
     4: return
  LineNumberTable:
    line 1: 0

public static void main(java.lang.String[]);
descriptor: ([Ljava/lang/String;)V
flags: (0x0009) ACC_PUBLIC, ACC_STATIC
Code:
  stack=2, locals=2, args_size=1
     0: aload_0
     1: arraylength
     2: iconst_1
     3: if_icmplt     37
     6: aload_0
     7: iconst_0
     8: aaload
     9: astore_1
    10: aload_1
    11: ldc           #2                  // String {Redacted}
    13: invokevirtual #3                  // Method java/lang/String.equals:(Ljava/lang/Object;)Z
    16: ifeq          28
    19: getstatic     #4                  // Field java/lang/System.out:Ljava/io/PrintStream;
    22: ldc           #5                  // String You guessed the correct password
    24: invokevirtual #6                  // Method java/io/PrintStream.println:(Ljava/lang/String;)V
    27: return
    28: getstatic     #4                  // Field java/lang/System.out:Ljava/io/PrintStream;
    31: ldc           #7                  // String You guessed the wrong password
    33: invokevirtual #6                  // Method java/io/PrintStream.println:(Ljava/lang/String;)V
    36: return
    37: getstatic     #4                  // Field java/lang/System.out:Ljava/io/PrintStream;
    40: ldc           #8                  // String Please supply a password
    42: invokevirtual #6                  // Method java/io/PrintStream.println:(Ljava/lang/String;)V
    45: return
  LineNumberTable:
    line 3: 0
    line 4: 6
    line 6: 10
    line 7: 19
    line 8: 27
    line 10: 28
    line 11: 36
    line 14: 37
    line 15: 45
  StackMapTable: number_of_entries = 2
    frame_type = 252 /* append */
      offset_delta = 28
      locals = [ class java/lang/String ]
    frame_type = 250 /* chop */
      offset_delta = 8
```

In the `main()` function, we see that **the stack has added a value (Instruction `ldc`) from constant pool `#2`.**

Then, **the `invokevirtual` instruction invoked method `java/lang/String.equals`**, which is a method that compares this string to the specified object:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/JVM-Reverse-Engineering/images/Pasted%20image%2020230203193724.png)

**If the password string is incorrect, then use `ifeq` instruction to jump to branch offset `28`**, which is printing the string "You guessed the wrong password".

***Armed with above information, the constant pool `#2` string value is the correct password!***
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task3)-[2023.02.03|19:29:35(HKT)]
└> java PasswordProtectedApplication {Redacted}    
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
You guessed the correct password
```

## Task 4 - Basic String Obfuscation

Like the previous task, this program takes a password as an argument, and outputs whether or not it is correct. This time the string is not directly present in the class file, and you will need to use either a decompiler, bytecode analysis or virtualisation to find it.

---

### Question 1 - What is the correct password?

**In this task, we can download a file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/JVM-Reverse-Engineering/images/Pasted%20image%2020230203194136.png)

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task4)-[2023.02.03|19:41:49(HKT)]
└> file BasicStringObfuscation.class      
BasicStringObfuscation.class: compiled Java class data, version 52.0 (Java 1.8)
```

**Again, use `javap` to view to bytecodes:**
```java
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task4)-[2023.02.03|19:42:27(HKT)]
└> javap -v -p BasicStringObfuscation      
[...]
Constant pool:
   #1 = Methodref          #14.#31        // java/lang/Object."<init>":()V
   #2 = Class              #32            // BasicStringObfuscation
   #3 = String             #33            // aRa2lPT6A6gIqm4RE
   #4 = Methodref          #2.#34         // BasicStringObfuscation.xor:(Ljava/lang/String;)Ljava/lang/String;
   #5 = Methodref          #12.#35        // java/lang/String.equals:(Ljava/lang/Object;)Z
   #6 = Fieldref           #36.#37        // java/lang/System.out:Ljava/io/PrintStream;
   #7 = String             #38            // Correct!
   #8 = Methodref          #39.#40        // java/io/PrintStream.println:(Ljava/lang/String;)V
   #9 = String             #41            // Incorrect
  #10 = String             #42            // Please provide a password
  #11 = Methodref          #12.#43        // java/lang/String.toCharArray:()[C
  #12 = Class              #44            // java/lang/String
  #13 = Methodref          #12.#45        // java/lang/String."<init>":([C)V
  #14 = Class              #46            // java/lang/Object
  #15 = Utf8               correctPassword
  #16 = Utf8               Ljava/lang/String;
  #17 = Utf8               ConstantValue
  #18 = Utf8               <init>
  #19 = Utf8               ()V
  #20 = Utf8               Code
  #21 = Utf8               LineNumberTable
  #22 = Utf8               main
  #23 = Utf8               ([Ljava/lang/String;)V
  #24 = Utf8               StackMapTable
  #25 = Class              #44            // java/lang/String
  #26 = Utf8               xor
  #27 = Utf8               (Ljava/lang/String;)Ljava/lang/String;
  #28 = Class              #47            // "[C"
  #29 = Utf8               SourceFile
  #30 = Utf8               BasicStringObfuscation.java
  #31 = NameAndType        #18:#19        // "<init>":()V
  #32 = Utf8               BasicStringObfuscation
  #33 = Utf8               aRa2lPT6A6gIqm4RE
  #34 = NameAndType        #26:#27        // xor:(Ljava/lang/String;)Ljava/lang/String;
  #35 = NameAndType        #48:#49        // equals:(Ljava/lang/Object;)Z
  #36 = Class              #50            // java/lang/System
  #37 = NameAndType        #51:#52        // out:Ljava/io/PrintStream;
  #38 = Utf8               Correct!
  #39 = Class              #53            // java/io/PrintStream
  #40 = NameAndType        #54:#55        // println:(Ljava/lang/String;)V
  #41 = Utf8               Incorrect
  #42 = Utf8               Please provide a password
  #43 = NameAndType        #56:#57        // toCharArray:()[C
  #44 = Utf8               java/lang/String
  #45 = NameAndType        #18:#58        // "<init>":([C)V
  #46 = Utf8               java/lang/Object
  #47 = Utf8               [C
  #48 = Utf8               equals
  #49 = Utf8               (Ljava/lang/Object;)Z
  #50 = Utf8               java/lang/System
  #51 = Utf8               out
  #52 = Utf8               Ljava/io/PrintStream;
  #53 = Utf8               java/io/PrintStream
  #54 = Utf8               println
  #55 = Utf8               (Ljava/lang/String;)V
  #56 = Utf8               toCharArray
  #57 = Utf8               ()[C
  #58 = Utf8               ([C)V
```

```java
private static final java.lang.String correctPassword;
descriptor: Ljava/lang/String;
flags: (0x001a) ACC_PRIVATE, ACC_STATIC, ACC_FINAL
ConstantValue: String aRa2lPT6A6gIqm4RE

public BasicStringObfuscation();
descriptor: ()V
flags: (0x0001) ACC_PUBLIC
Code:
  stack=1, locals=1, args_size=1
     0: aload_0
     1: invokespecial #1                  // Method java/lang/Object."<init>":()V
     4: return
  LineNumberTable:
    line 1: 0

public static void main(java.lang.String[]);
descriptor: ([Ljava/lang/String;)V
flags: (0x0009) ACC_PUBLIC, ACC_STATIC
Code:
  stack=2, locals=2, args_size=1
     0: aload_0
     1: arraylength
     2: iconst_1
     3: if_icmplt     42
     6: aload_0
     7: iconst_0
     8: aaload
     9: astore_1
    10: ldc           #3                  // String aRa2lPT6A6gIqm4RE
    12: invokestatic  #4                  // Method xor:(Ljava/lang/String;)Ljava/lang/String;
    15: aload_1
    16: invokevirtual #5                  // Method java/lang/String.equals:(Ljava/lang/Object;)Z
    19: ifeq          33
    22: getstatic     #6                  // Field java/lang/System.out:Ljava/io/PrintStream;
    25: ldc           #7                  // String Correct!
    27: invokevirtual #8                  // Method java/io/PrintStream.println:(Ljava/lang/String;)V
    30: goto          41
    33: getstatic     #6                  // Field java/lang/System.out:Ljava/io/PrintStream;
    36: ldc           #9                  // String Incorrect
    38: invokevirtual #8                  // Method java/io/PrintStream.println:(Ljava/lang/String;)V
    41: return
    42: getstatic     #6                  // Field java/lang/System.out:Ljava/io/PrintStream;
    45: ldc           #10                 // String Please provide a password
    47: invokevirtual #8                  // Method java/io/PrintStream.println:(Ljava/lang/String;)V
    50: return
  LineNumberTable:
    line 5: 0
    line 6: 6
    line 8: 10
    line 9: 22
    line 11: 33
    line 13: 41
    line 15: 42
    line 16: 50
  StackMapTable: number_of_entries = 3
    frame_type = 252 /* append */
      offset_delta = 33
      locals = [ class java/lang/String ]
    frame_type = 7 /* same */
    frame_type = 250 /* chop */
      offset_delta = 0

private static java.lang.String xor(java.lang.String);
descriptor: (Ljava/lang/String;)Ljava/lang/String;
flags: (0x000a) ACC_PRIVATE, ACC_STATIC
Code:
  stack=5, locals=5, args_size=1
     0: aload_0
     1: invokevirtual #11                 // Method java/lang/String.toCharArray:()[C
     4: astore_1
     5: aload_1
     6: arraylength
     7: newarray       char
     9: astore_2
    10: iconst_0
    11: istore_3
    12: iload_3
    13: aload_2
    14: arraylength
    15: if_icmpge     39
    18: aload_1
    19: iload_3
    20: caload
    21: istore        4
    23: aload_2
    24: iload_3
    25: iload         4
    27: iload_3
    28: iconst_3
    29: irem
    30: ixor
    31: i2c
    32: castore
    33: iinc          3, 1
    36: goto          12
    39: new           #12                 // class java/lang/String
    42: dup
    43: aload_2
    44: invokespecial #13                 // Method java/lang/String."<init>":([C)V
    47: areturn
  LineNumberTable:
    line 19: 0
    line 20: 5
    line 22: 10
    line 23: 18
    line 24: 23
    line 22: 33
    line 26: 39
  StackMapTable: number_of_entries = 2
    frame_type = 254 /* append */
      offset_delta = 12
      locals = [ class "[C", class "[C", int ]
    frame_type = 250 /* chop */
      offset_delta = 26
```

Right off the bat, we again can see the password is in the constant pool `#3`.

**However, it's being XOR'ed.**

**Since XOR'ing string can be very complex, we can use a decompiler tool called `jd-gui`:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task4)-[2023.02.03|19:46:57(HKT)]
└> jd-gui BasicStringObfuscation.class
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/JVM-Reverse-Engineering/images/Pasted%20image%2020230203194829.png)

**Decompiled:**
```java
public class BasicStringObfuscation {  
  private static final String correctPassword = "aRa2lPT6A6gIqm4RE";  
    
  public static void main(String[] paramArrayOfString) {  
    if (paramArrayOfString.length >= 1) {  
      String str = paramArrayOfString[0];  
      if (xor("aRa2lPT6A6gIqm4RE").equals(str)) {  
        System.out.println("Correct!");  
      } else {  
        System.out.println("Incorrect");  
      }   
      return;  
    }   
    System.out.println("Please provide a password");  
  }  
    
  private static String xor(String paramString) {  
    char[] arrayOfChar1 = paramString.toCharArray();  
    char[] arrayOfChar2 = new char[arrayOfChar1.length];  
    for (byte b = 0; b < arrayOfChar2.length; b++) {  
      char c = arrayOfChar1[b];  
      arrayOfChar2[b] = (char)(c ^ b % 3);  
    }   
    return new String(arrayOfChar2);  
  }  
}
```

In here, we see that every characters in correct password is being XOR'ed by:

- ${C} \oplus {B} \mod 3$

**Armed with above information, we can XOR the correct password in Python:**
```py
#!/usr/bin/env python3

correctPassword = 'aRa2lPT6A6gIqm4RE'
correctPasswordLength = len(correctPassword)

xoredCorrectPassword = ''
for b in range(correctPasswordLength):
    xored = ord(correctPassword[b]) ^ b % 3
    xoredCorrectPassword += chr(xored)
else:
    print(xoredCorrectPassword)
```

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task4)-[2023.02.03|19:57:24(HKT)]
└> python3 solve.py                       
{Redacted}
```

**Let's verify that!**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task4)-[2023.02.03|19:57:44(HKT)]
└> java BasicStringObfuscation {Redacted}
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Correct!
```

It's correct!

## Task 5 - Advanced bytecode manipulation

[ASM](https://asm.ow2.io/) is a powerful open source library for manipulating bytecode. It gives a high level representation of bytecode that is easy to parse and modify.

You can use asm to programmatically remove obfuscation in java applications. [Java Deobfuscator](https://github.com/java-deobfuscator/deobfuscator) is an open source project that aims to use ASM to remove common obfuscation. They provide already implemented transformers, as well as the ability to make your own. A simple way to solve advanced crackmes like the one below is to virtualise method calls, for example the method calls to decrypt the strings. Java deobfuscator provides the necessary tools to do this, and there are prewritten examples that you can adapt to any program.

## Task 6 - Advanced String Obfuscation

This program follows the same logic as the previous task, however it has a custom obfuscation layered on top. You might require a decompiler for this, as well as custom tools. This uses anti virtualisation techniques as well, so be warned.

### Question 1 - Find the correct password

**In this task, we can download a file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/JVM-Reverse-Engineering/images/Pasted%20image%2020230203200118.png)

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task6)-[2023.02.03|20:01:27(HKT)]
└> file BasicStringObfuscation-obf.jar 
BasicStringObfuscation-obf.jar: Java archive data (JAR)
```

As you can see, it's a JAR file, which compresses `class` and metadata file into a JAR file.

**We can try to provide an incorrect password via `java -jar`:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task6)-[2023.02.03|20:04:02(HKT)]
└> java -jar BasicStringObfuscation-obf.jar test
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Incorrect
```

**Again, decompile it via `jd-gui`:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task6)-[2023.02.03|20:05:41(HKT)]
└> jd-gui BasicStringObfuscation-obf.jar
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/JVM-Reverse-Engineering/images/Pasted%20image%2020230203200621.png)

However, this time it's heavily obfuscated.

**0.class:**
```java
public class 0 {  
  public static String c = 1.a(5, 78);  
    
  public static void main(String[] paramArrayOfString) {  
    if (paramArrayOfString.length >= ((int)1506594314L ^ 0x59CCCE0B)) {  
      null;  
      String str = 1.a(0, 100);  
      try {  
        str = paramArrayOfString[(int)-753045066L ^ 0xD31D71B6];  
      } catch (IndexOutOfBoundsException indexOutOfBoundsException) {  
        throw indexOutOfBoundsException;  
      }   
      null;  
      if (c(1.a(1, 95)).equals(str)) {  
        System.out.println(1.a(2, 2));  
      } else {  
        System.out.println(1.a(3, 38));  
      }   
      return;  
    }   
    System.out.println(1.a(4, 87));  
  }  
    
  public static String c(String paramString) {  
    char[] arrayOfChar1 = paramString.toCharArray();  
    char[] arrayOfChar2 = new char[arrayOfChar1.length];  
    for (int i = (int)1072331622L ^ 0x3FEA7B66; i < arrayOfChar2.length; i++) {  
      char c = arrayOfChar1[i];  
      arrayOfChar2[i] = (char)(c ^ i & ((int)-1108647316L ^ 0xBDEB626E));  
    }   
    return new String(arrayOfChar2);  
  }  
}
```

**1.class:**
```java
public final class 1 {  
  private static final String[] a = new String[12];  
    
  static {  
    a[0] = "";  
    a[2] = "[>T׷ֈ5\t\006הי68\001ךמRh\003׌րG0\006֍א0\032";  
    a[4] = "AmB׋֌av\021";  
    a[6] = "KHSז֛pCS׍";  
    a[8] = "R;Uט֚gw@׋ֆt>Tל׉cw@ט֚q _׋֍";  
    a[10] = "[/T໧ຸ5\030\006ໄ໩6)\001໊໮Ry\003ໜະG!\006ຝ໠0\013";  
  }  
    
  public static String a(int paramInt1, int paramInt2) {  
    if (c.3 != 0) {  
      null;  
    } else {  
      null;  
      Object object = null;  
      Thread thread = null;  
      StackTraceElement[] arrayOfStackTraceElement = null;  
      int i = 0;  
      int j = 0;  
      char[] arrayOfChar1 = null;  
      char[] arrayOfChar2 = null;  
      byte b2 = 0;  
      byte b1 = 0;  
      while (true) {  
        switch (b1) {  
          default:  
            (YourMum)null;  
          case true:  
            thread = Thread.currentThread();  
            b1 = 3;  
          case true:  
            arrayOfChar1 = a[paramInt1 * 2].toCharArray();  
            arrayOfChar2 = new char[arrayOfChar1.length];  
            b1 = 8;  
          case true:  
            b2 = 0;  
            if (b2 < arrayOfChar1.length) {  
              switch (b2 % 5) {  
                case 5:  
                  
                case 3:  
                  
                case 0:  
                  
                case 4:  
                  
                case 2:  
                  
                case 1:  
                case 0:  
                  break;  
              }   
            } else {  
              b1 = 1;  
              continue;  
            }   
            throw null;  
          case true:  
            a[paramInt1 * 2 + 1] = new String(arrayOfChar2);  
            return new String(arrayOfChar2);  
          case true:  
            j = arrayOfStackTraceElement[2].getMethodName().hashCode();  
            b1 = 7;  
          case false:  
          case true:  
            if (a[paramInt1 * 2 + 1] != null)  
              return a[paramInt1 * 2 + 1];   
            a[paramInt1 * 2 + 1];  
            b1 = 2;  
          case true:  
            arrayOfStackTraceElement = thread.getStackTrace();  
            b1 = 4;  
          case true:  
            i = arrayOfStackTraceElement[2].getClassName().hashCode();  
            b1 = 5;  
        }   
      }   
    }   
    arrayOfChar1[b2] ^ paramInt2;  
  }  
}
```

**c.class:**
```java
public final class c {  
  public static int c = 1068985474;  
    
  public static int 0 = 813209166;  
    
  public static int 1 = 1849073100;  
    
  public static int 2 = 636875190;  
    
  public static int 3 = 0;  
    
  static {  
    2 = 1;  
    1 = 1;  
    0 = -1;  
    c = -1;  
  }  
}
```

**In the `0.class`, we see this:**
```java
  public static void main(String[] paramArrayOfString) {  
    if (paramArrayOfString.length >= ((int)1506594314L ^ 0x59CCCE0B)) {  
      null;  
      String str = 1.a(0, 100);  
      try {  
        str = paramArrayOfString[(int)-753045066L ^ 0xD31D71B6];  
      } catch (IndexOutOfBoundsException indexOutOfBoundsException) {  
        throw indexOutOfBoundsException;  
      }   
      null;  
      if (c(1.a(1, 95)).equals(str)) {  
        System.out.println(1.a(2, 2));  
      } else {  
        System.out.println(1.a(3, 38));  
      }   
      return;  
    }   
    System.out.println(1.a(4, 87));  
  }
```

It first check the parameter length is greter or equal to 1 ($1506594314 \oplus 0x59CCCE0B = 1$).

Then, `str` looks like is the correct password from class `1` method `a`? (`1.a(0, 100)`)

**After that, checks `c(1.a(1, 95))` is equal to the correct password or not. If correct, print `1.a(2, 2)` ("Correct"?) . If not correct, that print `a.1(3, 38)` ("Incorrect").**

Finally, the `1.a(4, 87)` should outputs "Please provide a password", as we didn't provide any parameter:

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task6)-[2023.02.08|15:34:06(HKT)]
└> java -jar BasicStringObfuscation-obf.jar     
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Please provide a password
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task6)-[2023.02.08|15:34:13(HKT)]
└> java -jar BasicStringObfuscation-obf.jar test
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Incorrect
```

Armed with above information, **the `1.a(1, 95)` is the correct password we need to parse in**. However, **it was wrapped by a method called `c`, which XOR'ing each characters.**

Now, static reverse engineering would be very painful.

So, **dynamic reverse engineering** is the way to go!

To do so, **I'll use [Krakatau](https://github.com/Storyyeller/Krakatau)**, a Java decompiler, assembler, and disassembler.

**Decompile, which outputs Java bytecodes:** (Like using `javap`)
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task6)-[2023.02.08|15:47:02(HKT)]
└> python2 /opt/Krakatau/disassemble.py -out disassembled.zip -roundtrip BasicStringObfuscation-obf.jar 
[...]
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task6)-[2023.02.08|15:55:17(HKT)]
└> mkdir disassembled
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task6)-[2023.02.08|15:55:43(HKT)]
└> unzip disassembled.zip -d disassembled 
Archive:  disassembled.zip
 extracting: disassembled/0.j        
 extracting: disassembled/1.j        
 extracting: disassembled/c.j
```

**By using `cat` to `0.j`, we can see the following bytecodes:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task6/disassembled)-[2023.02.08|16:00:55(HKT)]
└> cat 0.j 
[...]
L72:    iconst_3 
L73:    bipush 38 
L75:    invokestatic [15] 
L78:    invokevirtual [48] 
[...]
```

These bytecodes are `1.a(3, 38)`, and the `invokevirtual` JVM instruction is calling `println()` function.

**That being said, we can find the `println()` function for the "Please provide a password" (No parameter is given), then outputs the `1.a(1, 95)`, which is the correct password.**

**`println()` function for the "Please provide a password":** (`1.a(4, 87)`)
```java
L82:    getstatic [42] 
L85:    iconst_4 
L86:    bipush 87 
L88:    invokestatic [15] 
L91:    invokevirtual [48] 
L94:    return
```

**Modify instruction from `iconst_4`, `bipush 87` (`1.a(4, 87)`) to `iconst_1`, `bipush 95` (`1.a(1, 95)`):**
```java
L82:    getstatic [42] 
L85:    iconst_1 
L86:    bipush 95 
L88:    invokestatic [15] 
L91:    invokevirtual [48] 
L94:    return
```

After that, remember the `1.a(1, 95)` is being XOR'ed by function `c()`?

**Let's add a new `invokestatic` instruction to invoke that `c()` function!!**

**By checking the bytecodes, we found this:**
```java
[...]
.const [2] = Utf8 '0' 
.const [3] = Class [2] 
.const [4] = Utf8 java/lang/Object 
.const [5] = Class [4] 
.const [6] = Utf8 c
[...]
.const [28] = Utf8 (Ljava/lang/String;)Ljava/lang/String; 
.const [29] = NameAndType [6] [28] 
.const [30] = Method [3] [29]
```

When `[30]` is used, it'll invoke method `[3]`, `[29]`, which finally call function `c()`.

**Let's modify the bytecodes:**
```java
L82:    getstatic [42] 
L85:    iconst_1 
L86:    bipush 95 
L88:    invokestatic [15] 
L89:    invokestatic [30] 
L91:    invokevirtual [48] 
L94:    return
```

**Then, we can use Krakatau's `assemble.py` to get the compiled JAR file:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task6)-[2023.02.08|16:10:33(HKT)]
└> python2 /opt/Krakatau/assemble.py -out result.jar -r disassembled/
[...]
```

**However, when we use `java -jar`, it outputs:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task6)-[2023.02.08|16:18:59(HKT)]
└> java -jar result.jar                         
Error: Invalid or corrupt jarfile result.jar
```

**To fix that, we can use the `-cp` flag. This will help the `java` to point to the main function (`0`):**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task6)-[2023.02.08|16:30:37(HKT)]
└> java -cp result.jar 0
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
{Redacted}
```

Boom! We got it!

**Let's verify that:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task6)-[2023.02.08|16:30:15(HKT)]
└> java -jar BasicStringObfuscation-obf.jar {Redacted}                           
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Correct!
```

Nice!

## Task 7 - Extreme Obf

This final jar has nearly every exploit I know packed into it. I dont know of any decompilers that will work for it. You will have to use custom tools and bytecode analysis to pick apart this one.

Same format as the previous tasks, takes one argument as the password.

---

**In this task, we can download a file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/JVM-Reverse-Engineering/images/Pasted%20image%2020230208163250.png)

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task7)-[2023.02.08|16:32:15(HKT)]
└> file BasicStringObfuscation-obf.jar 
BasicStringObfuscation-obf.jar: Java archive data (JAR)
```

### Question 1 - What is the correct password?

**Again, try to use `jd-gui` to get a decompiled version of that JAR file:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task7)-[2023.02.08|16:33:33(HKT)]
└> jd-gui BasicStringObfuscation-obf.jar
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/JVM-Reverse-Engineering/images/Pasted%20image%2020230208163803.png)

However, there is a weird file??

**Hmm... Let's `unzip` it:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task7)-[2023.02.08|16:39:44(HKT)]
└> unzip BasicStringObfuscation-obf.jar
Archive:  BasicStringObfuscation-obf.jar
PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP[...]
```

What??

It seems like the JAR file's byte has been modified, thus it's corrupted.

**Can we use `java -jar` to run it?**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task7)-[2023.02.08|16:39:56(HKT)]
└> java -jar BasicStringObfuscation-obf.jar test
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Incorrect
```

We can.

**Umm... Let's try to use `binwalk` to extract the files inside the JAR:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task7)-[2023.02.08|16:41:47(HKT)]
└> binwalk -e BasicStringObfuscation-obf.jar 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
79            0x4F            Zip archive data, at least v2.0 to extract, name: META-INF/MANIFEST.MF
163           0xA3            Zip archive data, at least v2.0 to extract, name: 0.class
219           0xDB            Zip archive data, at least v2.0 to extract, name: 0.class
274           0x112           Zip archive data, at least v2.0 to extract, name: 0.class
2560          0xA00           Zip archive data, at least v2.0 to extract, name: 1.class
2616          0xA38           Zip archive data, at least v2.0 to extract, name: 1.class
2671          0xA6F           Zip archive data, at least v2.0 to extract, name: 1.class
4409          0x1139          Zip archive data, at least v2.0 to extract, name: c.class
5232          0x1470          End of Zip archive, footer length: 32022, comment: "PPP[...]"
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task7)-[2023.02.08|16:42:19(HKT)]
└> ls -lah _BasicStringObfuscation-obf.jar.extracted/
total 68K
drwxr-xr-x 3 siunam nam 4.0K Feb  8 16:42 .
drwxr-xr-x 3 siunam nam 4.0K Feb  8 16:42 ..
-rw-r--r-- 1 siunam nam 4.2K Mar 12  2020 0.class
-rw-r--r-- 1 siunam nam 3.0K Mar 12  2020 1.class
-rw-r--r-- 1 siunam nam  37K Feb  8 16:42 4F.zip
-rw-r--r-- 1 siunam nam  339 Mar 12  2020 c.class
drwxr-xr-x 2 siunam nam 4.0K Feb  8 16:42 META-INF
```

No idea what the `4F.zip` is.

**In `/META-INF`, we can see which class file is the main class:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task7/_BasicStringObfuscation-obf.jar.extracted)-[2023.02.08|16:43:42(HKT)]
└> cat META-INF/MANIFEST.MF 
Main-Class: 0
```

`0.class` is the main class.

Now, we can do the same thing in the previous task: Use Krakatau's `disassemble.py` to get the bytecode, modify the bytecode, then use `assemble.py` to compile to JAR.

- **Get the bytecode:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task7/_BasicStringObfuscation-obf.jar.extracted)-[2023.02.08|16:49:30(HKT)]
└> mkdir BasicStringObfuscation-obf                          
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task7/_BasicStringObfuscation-obf.jar.extracted)-[2023.02.08|16:50:40(HKT)]
└> python2 /opt/Krakatau/disassemble.py -out BasicStringObfuscation-obf/0.j -roundtrip 0.class
[...]
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task7/_BasicStringObfuscation-obf.jar.extracted)-[2023.02.08|16:51:06(HKT)]
└> python2 /opt/Krakatau/disassemble.py -out BasicStringObfuscation-obf/1.j -roundtrip 1.class
[...]
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task7/_BasicStringObfuscation-obf.jar.extracted)-[2023.02.08|16:51:11(HKT)]
└> python2 /opt/Krakatau/disassemble.py -out BasicStringObfuscation-obf/c.j -roundtrip c.class
[...]
```

- **Modify the bytecode:**

**By looking at the bytecodes, they are heavily obfuscated:**
```java
[...]
L84:    iconst_0 
L85:    bipush 54 
L87:    ldc [55] 
L89:    pop 
L90:    goto L94 

        .stack full 
            locals 
            stack Object [38] 
        .end stack 
L93:    athrow 

        .stack full 
            locals Object [102] 
            stack Integer Integer 
        .end stack 
L94:    invokestatic [59] 
L97:    goto L101 

        .stack stack_1 Object [38] 
L100:   athrow 

        .stack stack_1 Object [78] 
L101:   astore_1 
        .catch [11] from L102 to L112 using L115 
        .catch [0] from L8 to L23 using L437 
L102:   aload_0 
L103:   ldc2_w [60] 
L106:   l2i 
L107:   ldc [62] 
L109:   ixor 
L110:   aaload 
L111:   astore_1 
L112:   goto L162 
[...]
```

Basically it added `goto` instruction in many places.

**However, the code flow is the same in task 6:**
```java
L321:   getstatic [91] 
L324:   iconst_3 
L325:   bipush 95 
L327:   goto L331 
```

According to task 6, this pattern is invoking method `1.a(3, 95)` from class `1`.

**And we can see there are 6 of them:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/JVM-Reverse-Engineering/images/Pasted%20image%2020230208165937.png)

Now, let's try to **find which of those patterns return "Please provide a password"**.

**After fumbling around, I found that there's 4 `invokevirtual [97]` instructions in the above pattern are being invoked:**
```java
[...]
L411:   athrow 

        .stack full 
            locals Object [102] 
            stack Object [93] Object [78] 
        .end stack 
L412:   invokevirtual [97] 
L415:   goto L419 

        .stack stack_1 Object [23] 
L418:   athrow 

        .stack same 
L419:   return 
```

```java
[...]
.const [94] = Utf8 println 
.const [95] = Utf8 (Ljava/lang/String;)V 
.const [96] = NameAndType [94] [95] 
.const [97] = Method [93] [96]
[...]
```

Nice! We found the `println()` function is `invokevirtual [97]`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/JVM-Reverse-Engineering/images/Pasted%20image%2020230209095709.png)

And there are 3 of them! Which should be "Please provide a password" when no parameter is provided, "Incorrect" when the password is incorrect, and "Correct!".

**In the disassembled bytecodes, we found 6 `iconst` patterns:**
```java
L84:    iconst_0 
L85:    bipush 54 
[...]
L162:   iconst_1 
L163:   bipush 77 
[...]
L291:   iconst_2 
L292:   bipush 19 
[...]
L324:   iconst_3 
L325:   bipush 95 
[...]
L353:   iconst_4 
L354:   bipush 42 
[...]
L30:    iconst_5 
L31:    bipush 98 
```

In here, we can exclude `0, 54`, `1, 77`, `5, 98`, as they have no `invokevirtual [97]` instruction.

**Armed with above information, we can modify `2, 19`, `3, 95`, `4, 42` to the above excluded pattern.**

**Let's try `2, 19` first.**

**Original:**
```java
L291:   iconst_2 
L292:   bipush 19 
```

**Modified:**
```java
L291:   iconst_0 
L292:   bipush 54 
```

**Then, compile and run it:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task7/_BasicStringObfuscation-obf.jar.extracted)-[2023.02.09|10:06:24(HKT)]
└> python2 /opt/Krakatau/assemble.py -out result.jar -r BasicStringObfuscation-obf
[...]
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task7/_BasicStringObfuscation-obf.jar.extracted)-[2023.02.09|10:12:10(HKT)]
└> java -cp result.jar 0                                                          
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Please provide a password
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task7/_BasicStringObfuscation-obf.jar.extracted)-[2023.02.09|10:12:17(HKT)]
└> java -cp result.jar 0 test
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Incorrect
```

It seems like `2, 19` and `0, 54` are neither "Please provide a password" nor "Incorrect".

**After that, repeat the same step until we found something interesting.**

**Original:**
```java
L353:   iconst_4 
L354:   bipush 42 
```

**Modified:**
```java
L353:   iconst_1 
L354:   bipush 77 
```

**Compile and run:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task7/_BasicStringObfuscation-obf.jar.extracted)-[2023.02.09|10:12:20(HKT)]
└> python2 /opt/Krakatau/assemble.py -out result.jar -r BasicStringObfuscation-obf
[...]
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task7/_BasicStringObfuscation-obf.jar.extracted)-[2023.02.09|10:15:10(HKT)]
└> java -cp result.jar 0                                                          
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
WpUtETnF1JGrDkSsTd5G1w2dN0h
```

Oh! We found it!

***The `4, 42` is the place that outputs the "Please provide a password", and we modify it to `1, 77`, which outputs the correct password!***

**However, when you verify it:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task7)-[2023.02.09|10:16:36(HKT)]
└> java -jar BasicStringObfuscation-obf.jar WpUtETnF1JGrDkSsTd5G1w2dN0h
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Incorrect
```

It's still incorrect.

Based on what we've found in task 6, **the correct password is being XOR'ed by a function called `c()`.**

**Armed with above information, let's follow the original `1, 77` bytecodes!**
```java
L162:   iconst_1 
L163:   bipush 77 
L165:   goto L169 
[...]
L169:   invokestatic [59] 
L172:   goto L176 
[...]
L176:   getstatic [70] 
L179:   ifle L187 
L182:   ldc [71] 
L184:   goto L189 
[...]
L189:   ldc [73] 
L191:   ixor 
L192:   lookupswitch 
            -1193931379 : L187 
            -225155977 : L220 
            default : L426 


        .stack stack_1 Object [78] 
L220:   goto L224 
[...]
L224:   invokestatic [76] 
L227:   goto L231 
[...]
L231:   aload_1 
L232:   goto L236 
[...]
L236:   invokevirtual [82] 
L239:   goto L243 
[...]
L243:   ifeq L321 
L246:   getstatic [40] 
L249:   ifle L257 
L252:   ldc [83] 
L254:   goto L259 
[...]
L259:   ldc [85] 
L261:   ixor 
L262:   lookupswitch 
            1173906090 : L424 
            1418467848 : L257 
            default : L288 


        .stack same 
L288:   getstatic [91] 
L291:   iconst_2 
L292:   bipush 19 
L294:   aconst_null 
L295:   pop 
L296:   goto L300 
[...]
L300:   invokestatic [59] 
L303:   goto L307 
[...]
L307:   goto L311 
[...]
L311:   invokevirtual [97] 
L314:   goto L318 
[...]
L318:   goto L349 
[...]
L349:   return
```

In here, we can just ignore `goto` instructions, as they are the obfuscuated one.

**Then, by looking at all the `invokestatic` instructions and their calling method, the `invokestatic [76]` stands out:**
```java
.const [2] = Utf8 '0' 
.const [3] = Class [2]
[...]
.const [6] = Utf8 c
[...]
.const [74] = Utf8 (Ljava/lang/String;)Ljava/lang/String;
.const [75] = NameAndType [6] [74] 
.const [76] = Method [3] [75]
```

**Basically the `invokestatic [76]` instruction is calling method `c.0` from class `c`.**

**Hence, we can add that `invokestatic [76]` instruction to the modified `4, 42`:**
```java
L353:   iconst_1 
L354:   bipush 77 
L356:   goto L360 
```

```java
L360:   invokestatic [59] 
L361:   invokestatic [76] 
L363:   goto L367 
```

**Finally, compile and run it:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task7/_BasicStringObfuscation-obf.jar.extracted)-[2023.02.09|10:15:13(HKT)]
└> python2 /opt/Krakatau/assemble.py -out result.jar -r BasicStringObfuscation-obf
[...]
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task7/_BasicStringObfuscation-obf.jar.extracted)-[2023.02.09|10:28:04(HKT)]
└> java -cp result.jar 0                                                          
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
{Redacted}
```

**Verify it:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/JVM-Reverse-Engineering/Task7)-[2023.02.09|10:28:11(HKT)]
└> java -jar BasicStringObfuscation-obf.jar {Redacted}
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Correct!
```

Boom!! We successfully found the correct password!!

# Conclusion

What we've learned:

1. Java Bytecode Reverse Engineering