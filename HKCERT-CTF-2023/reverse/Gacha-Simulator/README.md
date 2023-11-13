# Gacha Simulator

## Table of Contents

 1. [Overview](#overview)  
 2. [Background](#background)  
 3. [Find the Flag](#find-the-flag)  
    3.1. [What Is This PowerPoint File?](#what-is-this-powerpoint-file)  
    3.2. [Remove VBA Project Password](#remove-vba-project-password)  
    3.3. [Decrypt the URL](#decrypt-the-url)  
 4. [Conclusion](#conclusion)

## Overview

- 82 solves / 250 points
- Author: ozetta
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113143658.png)

Can you draw a five star card?

Attachment: [gacha-simulator_f18a9511d47a6f789577536c3781ea3d.zip](https://file.hkcert23.pwnable.hk/gacha-simulator_f18a9511d47a6f789577536c3781ea3d.zip)

**Note:** There is a guide for this challenge [here](https://hackmd.io/@blackb6a/hkcert-ctf-2023-ii-en-4e6150a89a1ff32c).

## Find the Flag

### What Is This PowerPoint File?

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/reverse/Gacha-Simulator/gacha-simulator_f18a9511d47a6f789577536c3781ea3d.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/reverse/Gacha-Simulator)-[2023.11.13|14:37:30(HKT)]
└> file gacha-simulator_f18a9511d47a6f789577536c3781ea3d.zip 
gacha-simulator_f18a9511d47a6f789577536c3781ea3d.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/reverse/Gacha-Simulator)-[2023.11.13|14:37:33(HKT)]
└> unzip gacha-simulator_f18a9511d47a6f789577536c3781ea3d.zip 
Archive:  gacha-simulator_f18a9511d47a6f789577536c3781ea3d.zip
  inflating: Gacha_Simulator.pptm    
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/reverse/Gacha-Simulator)-[2023.11.13|14:37:36(HKT)]
└> file Gacha_Simulator.pptm 
Gacha_Simulator.pptm: Microsoft PowerPoint 2007+
```

After researching, PPTM file is a Microsoft PowerPoint macro-enabled presentation file.

**With that said, let's open it up on a Windows machine:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113144049.png)

**In this PowerPoint file, we have to enable Macro and view in "Slide Show" to play the gacha simulator:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113144212.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113144225.png)

Upon viewing, a new window appeared.

Initially, we have 10 Gacha Tickets. Let's draw 1 by clicking the "Draw a Card" button:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113144328.png)

Hmm... I got a 1 Star card.

We can also see the gacha probability by clicking the "Gacha Probability" button:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113144436.png)

Hold up. **5 Stars card is 0%?** lol. How can we even obtain a 5 Stars card...

Let's exit the "Slide Show" and click the "Start" button:

[](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113144613.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113144644.png)

In here, we can view the VBA (Visual Basic for Application) project for this PowerPoint. However, **it's password protected:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113144751.png)

Uh... Can we remove that password??

### Remove VBA Project Password

Eventually, I found [this StackOverflow post](https://stackoverflow.com/questions/1026483/is-there-a-way-to-crack-the-password-on-an-excel-vba-project#answer-53358962) that talking about cracking the password on an Excel VBA Project.

Therefore, to remove the password on the VBA project, we need to:

- Open the file(s) that contain your locked VBA Projects (`Gacha_Simulator.pptm`):

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113145335.png)

- Create a new file with the same extension as the above (`.pptm`) and store the following VBA code in **`Module1`**:

```vbnet
Option Explicit

Private Const PAGE_EXECUTE_READWRITE = &H40

Private Declare PtrSafe Sub MoveMemory Lib "kernel32" Alias "RtlMoveMemory" _
(Destination As LongPtr, Source As LongPtr, ByVal Length As LongPtr)

Private Declare PtrSafe Function VirtualProtect Lib "kernel32" (lpAddress As LongPtr, _
ByVal dwSize As LongPtr, ByVal flNewProtect As LongPtr, lpflOldProtect As LongPtr) As LongPtr

Private Declare PtrSafe Function GetModuleHandleA Lib "kernel32" (ByVal lpModuleName As String) As LongPtr

Private Declare PtrSafe Function GetProcAddress Lib "kernel32" (ByVal hModule As LongPtr, _
ByVal lpProcName As String) As LongPtr

Private Declare PtrSafe Function DialogBoxParam Lib "user32" Alias "DialogBoxParamA" (ByVal hInstance As LongPtr, _
ByVal pTemplateName As LongPtr, ByVal hWndParent As LongPtr, _
ByVal lpDialogFunc As LongPtr, ByVal dwInitParam As LongPtr) As Integer

Dim HookBytes(0 To 11) As Byte
Dim OriginBytes(0 To 11) As Byte
Dim pFunc As LongPtr
Dim Flag As Boolean

Private Function GetPtr(ByVal Value As LongPtr) As LongPtr
    GetPtr = Value
End Function

Public Sub RecoverBytes()
    If Flag Then MoveMemory ByVal pFunc, ByVal VarPtr(OriginBytes(0)), 12
End Sub

Public Function Hook() As Boolean
    Dim TmpBytes(0 To 11) As Byte
    Dim p As LongPtr, osi As Byte
    Dim OriginProtect As LongPtr

    Hook = False

    #If Win64 Then
        osi = 1
    #Else
        osi = 0
    #End If

    pFunc = GetProcAddress(GetModuleHandleA("user32.dll"), "DialogBoxParamA")

    If VirtualProtect(ByVal pFunc, 12, PAGE_EXECUTE_READWRITE, OriginProtect) <> 0 Then

        MoveMemory ByVal VarPtr(TmpBytes(0)), ByVal pFunc, osi+1
        If TmpBytes(osi) <> &HB8 Then

            MoveMemory ByVal VarPtr(OriginBytes(0)), ByVal pFunc, 12

            p = GetPtr(AddressOf MyDialogBoxParam)

            If osi Then HookBytes(0) = &H48
            HookBytes(osi) = &HB8
            osi = osi + 1
            MoveMemory ByVal VarPtr(HookBytes(osi)), ByVal VarPtr(p), 4 * osi
            HookBytes(osi + 4 * osi) = &HFF
            HookBytes(osi + 4 * osi + 1) = &HE0

            MoveMemory ByVal pFunc, ByVal VarPtr(HookBytes(0)), 12
            Flag = True
            Hook = True
        End If
    End If
End Function

Private Function MyDialogBoxParam(ByVal hInstance As LongPtr, _
ByVal pTemplateName As LongPtr, ByVal hWndParent As LongPtr, _
ByVal lpDialogFunc As LongPtr, ByVal dwInitParam As LongPtr) As Integer

    If pTemplateName = 4070 Then
        MyDialogBoxParam = 1
    Else
        RecoverBytes
        MyDialogBoxParam = DialogBoxParam(hInstance, pTemplateName, _
                   hWndParent, lpDialogFunc, dwInitParam)
        Hook
    End If
End Function
```

**Create a new PowerPoint file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113145533.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113145606.png)

**Save as `.pptm` extension:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113145918.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113150213.png)

**Insert `Module1` in VBA project:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113145628.png)

> Note: If you didn't see the "Developer" tab, you can follow the steps in [https://support.microsoft.com/en-au/office/show-the-developer-tab-e1192344-5e56-4d45-931b-e5fd9bea2d45](https://support.microsoft.com/en-au/office/show-the-developer-tab-e1192344-5e56-4d45-931b-e5fd9bea2d45) to enable it.

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113145800.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113150355.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113150409.png)

**Copy and paste the VBA code to `Module1`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113150436.png)

- Insert `Module2` and copy and paste the following VBA code:

```vbnet
Sub unprotected()
    If Hook Then
        MsgBox "VBA Project is unprotected!", vbInformation, "*****"
    End If
End Sub
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113150526.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113150538.png)

- Run `Module2`'s `unprotected` function:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113150632.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113150640.png)

- Go back to the VBA project window and you should be able to view `Gacha_Simulator`'s VBA project:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113150752.png)

Nice!

Now, we can view all the VBA code by using the "View Code" submenu:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113150919.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113150941.png)

After reading it a little bit, we can know that:

**In `Slide1` object, when we view in "Slide Show" or click the `CommandButton1` ("Draw a Card") button, it'll call `Init` function in `Module2`:**
```vbnet
Sub OnSlideShowPageChange()
    Module2.Init
End Sub

Private Sub CommandButton1_Click()
    Module2.Init
End Sub
```

**In `Module2`, we can see how the `Init` function works:**
```vbnet
Global Key As String
Global Ticket As Integer
Global CardList() As String
Global CardStar() As String
Global CardName() As String
Global CardURL() As String
Global GachaN As Integer

Sub Init()
    On Error Resume Next
    GachaN = 0
    If Not IsNumeric(Application.ActivePresentation.Slides(1).NotesPage.Shapes(2).TextFrame.TextRange.Text) Then
        Ticket = 10
    Else
        Ticket = Int(Application.ActivePresentation.Slides(1).NotesPage.Shapes(2).TextFrame.TextRange.Text)
    End If
    
    UserForm1.Label2.Caption = "Remaining Gacha Tickets: " & Str(Ticket)
    
    Dim arrCards() As String
    arrCards = Split(Application.ActivePresentation.SlideMaster.Shapes(1).TextFrame.TextRange.Text, vbCr)
    Dim i As Long
    For i = LBound(arrCards) To UBound(arrCards)
        Row = Split(arrCards(i), "<>")
        ReDim Preserve CardStar(i)
        CardStar(i) = Row(1)
        ReDim Preserve CardName(i)
        CardName(i) = Row(2)
        ReDim Preserve CardURL(i)
        CardURL(i) = Module1.Decrypt(Row(3), Row(2))
    Next
    UserForm1.Show
End Sub
```

When the `Init` function is called, it'll initialize the `Ticket` to be `10`.

Then, the `arrCards` array is fetched from the content of a text box in the slide master and splitting it with the `<>` delimiter.

Next, the loop iterates over the elements of `arrCards` and splits each element further into separate parts using the `<>` delimiter. The star rating, card name, and encrypted URL are extracted and stored in the respective global arrays (`CardStar`, `CardName`, `CardURL`) using the `ReDim` Preserve statement to dynamically resize the arrays.

Finally, the `UserForm1.Show` statement displays the user form, allowing the user to interact with the Gacha Simulator window.

### Decrypt the URL

Hmm... Wait a minute... Why `CardURL` is decrypted??

**Let's look at the `Module1` code:**
```vbnet
[...]
Function B64Decode(b64Str)
    On Error Resume Next
    Set b64Dec = CreateObject("System.Security.Cryptography.FromBase64Transform")
    Set utf8 = CreateObject("System.Text.UTF8Encoding")
    bytes = utf8.GetBytes_4(b64Str)
    B64Decode = b64Dec.TransformFinalBlock((bytes), 0, LenB(bytes))
End Function
[...]
Function Decrypt(ciphertext, aesKey)
    On Error Resume Next
    Set aes = CreateObject("System.Security.Cryptography.RijndaelManaged")
    Set utf8 = CreateObject("System.Text.UTF8Encoding")
    aesKeyBytes = B64Decode(aesKey)
    ivBytes = utf8.GetBytes_4("ILikeHardcodedIV")
    cipherBytes = B64Decode(ciphertext)
    Set aesDec = aes.CreateDecryptor_2((aesKeyBytes), (ivBytes))
    plainBytes = aesDec.TransformFinalBlock((cipherBytes), 0, LenB(cipherBytes))
    Decrypt = utf8.GetString((plainBytes))
End Function
```

As you can see, the `Decrypt` function is using base64 and **AES** (Advanced Encryption Standard) CBC (Cipher Block Chaining) mode to decode and **decrypt the cipher text**.

In the above `Decrypt` function, we can see that the IV (Initialization Vector) is actually hard-coded (`ILikeHardcodedIV`).

In order to decrypt the `CardURL`, we can use the hard-coded IV value to decrypt the cipher text.

Or, if you wanna go with an easier route like me, **you can just print the decypted cipher text :D**

**To do so, we can use `MsgBox` function to pop up a message box, and with the value of the decypted cipher text on `Module1`:**
```vbnet
Sub Init()
    [...]
        ReDim Preserve CardURL(i)
        CardURL(i) = Module1.Decrypt(Row(3), Row(2))
        
        MsgBox CardURL(i)
    Next
    'UserForm1.Show
End Sub
```

In here, we add a new line `MsgBox CardURL(i)`, so that it'll pop up a message box with the decrypted `CardURL`. Then, we commented out `UserForm1.Show`, so the Gacha Simulator window won't appear.

Let's run it!

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113153103.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113153115.png)

**The first one looks normal, let's continue until we found something stands out:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231112132835.png)

Woah! **What's that `tar.bz2.top` domain??**

Let's go to that URL! (`https://tar.bz2.top/rr0oy1cq5e62yb3cyvavvhjkpqtrgqqis9lmm7dib5h8oiplxw4px2fpumzuehsx`)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231112132925.png)

Nice! We found the flag!

- **Flag: `hkcert23{FIl1liIIlI1III1lll1IlI11ag_Hmrnmmrnmmmrnmn}`**

## Conclusion

What we've learned:

1. Removing VBA project password & reverse engineering PowerPoint VBA code