---
title: Text and Typography
author: Cotes Chung
date: 2019-08-08 11:33:00 +0800
categories: [Blogging, Demo]
tags: [typography]
math: true
mermaid: true
image:
  src: https://cdn.jsdelivr.net/gh/cotes2020/chirpy-images/commons/devices-mockup.png
  width: 850
  height: 585
---

# Initial assessment

At Malware initial assessment using **PE-Studio**

<img src="https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/media/image1.png" style="width:6.5in;height:2.78681in" />

It looks like

-   This sample is **.NET** sample

-   This sample contains the magic byte “**MZ**” which means it’s
    executable

-   Follows **x32** architecture

By using **DIE** to analyze each section entropy

<img src="https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/media/image2.png" style="width:5.775in;height:3.43909in" />

We can conclude that both (.**text** , **.rsrc**) are packed

# Analysis

At first let’s start analyzing this file using **dnspy**

## **Resources**

<img src="https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/media/image3.png" style="width:3.50049in;height:0.90638in" />

The first interesting things we can observe from this image are
“**Costura**” & “**compressed**” strings!

So, the first question we should ask ourselves. What is **Costura**?

> **Costura** is an addon responsible for **Embedding dependencies as
> resources** on extensible tool for weaving .net assemblies called
> **Fody,** it is also loads itself with the same technique. After,
> reaching it’s github project <https://github.com/Fody/Costura> they
> also clarified that “**Embedded assemblies are compressed by
> default**” so “**compressed**” string makes sense now.

By opening “**Campos.properties.resources**” resource we can find

<img src="https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/media/image4.png" style="width:3.16667in;height:0.55208in" />

-   As we clarified before they are compressed so there is no reason to
    check them. But as a head up the malware maybe reside in one of
    them.

-   So, we should keep track of decompression/decryption and assembly
    loading functions to be able to unpack it.

## Execution analysis

<img src="https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/media/image5.png" style="width:4.40872in;height:0.90008in" />

<img src="https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/media/image6.png" style="width:4.98377in;height:1.64181in" />

<img src="https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/media/image7.png" style="width:5.47547in;height:4.05869in" />

<img src="https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/media/image8.png" style="width:6.5in;height:0.62292in" />

<img src="https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/media/image9.png" style="width:5.92791in;height:0.23962in" />

<img src="https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/media/image10.png" style="width:5.09211in;height:1.39179in" />

1.  We can see there that it accesses the resource
    (**MainWindow.nabexx + MainWindow.nabexx+ MainWindow.nabexx == “XX”
    +”XX” + “XX” == “XXXXXX”**)

2.  It decrypts it using **AES** algorithm using the resource (**XX**)
    as key

3.  Then it loads it into the memory

By extracting the two resources (**XX**, **XXXXXX**) and using this
simple python script, we can check what is loaded into the memory.

from Cryptodome.Cipher import AES

fk = open("XX", "rb")

key = fk.read()

bf = open("XXXXXX", "rb")

file = bf.read()

cipher = AES.new(key, AES.MODE_ECB)

new_file = open("file" , "wb")

new_file.write(cipher.decrypt(file))

new_file.close()

Continuing the analysis

<img src="https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/media/image11.png" style="width:6.16667in;height:2.07292in" />

<img src="https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/media/image12.png" style="width:5.4375in;height:4.28125in" />

It looks like it calls function **X** from **Class1** passing the
**loaded assembly** on it

<img src="https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/media/image13.png" style="width:6.5in;height:2.35in" />

Then it invokes the first method on the loaded assembly.by adding a
watch on **X.getMethods()\[0\]**

<img src="https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/media/image14.png" style="width:6.5in;height:0.54653in" />

It looks like that it invoked Function Void X() on X class on the loaded
assembly

Let’s go through extracted and loaded file analysis

# Extracted file Analysis

## **File initial assessment**

using **PE-Studio**

<img src="https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/media/image15.png" style="width:6.11667in;height:3.15in" />

It looks like

-   This sample is **.NET** sample

-   This sample contains the magic byte “**MZ**”, file type is **DLL**

-   Follows **x32** architecture

By using **DIE** to analyze each section entropy

<img src="https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/media/image16.png" style="width:5.35in;height:3.22829in" />

We can conclude that both .**text** section is packed

# Analysis

At first let’s start analyzing this file using **dnspy**

## **Resources**

<img src="https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/media/image17.png" style="width:2.50035in;height:0.7501in" />

As we have concluded before in the previous sample, it could be using
the same technique and there is something packed on these resources and
it decrypts it then it is loaded into memory.

## Execution analysis

As we have concluded in the previous section, Function **Void X()** in
class **X** was executed

<img src="https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/media/image18.png" style="width:4.95833in;height:1.14583in" />

It passes the executed file to the main function resided in **LOL**
class

**  
**

<img src="https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/media/image19.png" style="width:6.5in;height:3.63889in" />

<img src="https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/media/image20.png" style="width:1.78125in;height:0.32292in" />

For the second time, It it decrypting a resources and loading it them to
memory the memory, But life is too short to trace both unpacking
functions .so, We are going to replicated this code snippet into
compiler and extract both files writing them to disk

<img src="https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/media/image21.png" style="width:6.5in;height:2.51319in" />

# Analyzing Second file

## **File initial assessment**

using **PE-Studio**

<img src="https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/media/image22.png" style="width:6.5in;height:3.86667in" />

It looks like

-   This sample contains the magic byte “**MZ**”, file type is **DLL**

-   Follows **x32** architecture

By using **DIE** to

<img src="https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/media/image23.png" style="width:6.5in;height:1.15833in" />

<img src="https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/media/image24.png" style="width:4.84524in;height:2.81604in" />

It looks like

-   It’s **.NET** sample

-   This file is not packed

# Analysis

At first let’s start analyzing this file using **dnspy**

<img src="https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/media/image25.png" style="width:6.5in;height:2.96597in" />

By checking the main function there, it looks that this DLL is loaded
before the actual malware unpacking, to check for active antiviruses and
use it to avoid original malware detection

# Analyzing third file

## **File initial assessment**

using **PE-Studio**

<img src="https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/media/image26.png" style="width:6.5in;height:4.64028in" />

It looks like

-   This sample is **C++** sample

-   This sample contains the magic byte “**MZ**”, and it’s executable

-   Follows **x32** architecture

By using **DIE** to analyze each section entropy

<img src="https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/media/image27.png" style="width:4.93452in;height:3.01238in" />

Then finally this is the unpacked malware
