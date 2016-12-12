---
title: '[SECCON CTF 2016 Quals] jmper 300'
author: Naetw
tags:
  - pwn
  - SECCON CTF 2016
  - one-byte overflow
  - heap
  - ROP
categories:
  - write-ups
date: 2016-12-12 11:44:00
---

## Info
> Category: pwn
> Point: 300
> Solver: Naetw @ BambooFox

這題跟 cheer_msg 其實差不多，然後解法發現也跟以前解過的 [applestore](http://train.cs.nctu.edu.tw/problems/16) 很像，有紀錄以前的 writeup 真是太好了，記憶障礙的時候可以回顧一下

<!-- more -->

## Analyzing

64 bit ELF, FULL RELRO, 沒有 canary, 有 NX, 沒有 PIE

這支程式也很小，也用了一個從沒看過的 function，`setjmp` 跟 `longjmp`，簡單的介紹可以看 [jmp](http://www.cnblogs.com/hazir/p/c_setjmp_longjmp.html)，最後會需要瞭解這兩個 function 才能完成 exploit

main 裡面沒什麼重要的東西，除了 `setjmp` 之外，在 `setjmp` 之後會呼叫 `f`

`f` 蠻長的，但主要就是實作以下功能:

1. Add student
2. Name student
3. Write memo
4. Show name
5. Show memo
6. Bye


### Add student:

會先 `malloc` 一塊 48 bytes 的空間，第一格存著 student_num 也就是 ID，第六格存著存放名字的 heap address

### Name student:

這裡會先要求輸入 ID，然後就可以開始取名字，這裡存在 **one-byte overflow**，但是這裡我沒用到，這裡之後用來 overwrite return address

### Write memo:

這裡一樣先要求輸入 ID，這裡主要是改 student heap 的第二格到第四格，但是這裡存在著 **one-byte overflow**，所以我們可以利用這個來修改 name heap 的 address

### Show name:

就 dump 出 name

### Show memo:

同上

### Bye:

`exit(0)`

## Exploit

所以想法很簡單，用 A 學生 **one-byte overflow** 來修改 A 學生 name heap 的位置，把它指向 B 學生的第六格，也就是存放 B 學生 name heap 那格，接著用 A 學生來改 B 學生 name heap address，就可以進行 **leak info** 跟 **overwrite**

### First:

新增兩名學生，然後呼叫 A 學生的 `write_memo`，利用 **one-byte overflow** 把 A 學生 name heap address 改掉

student heap layout:

```
             +------------------+
             |.........prev_size|
             |..............size|
studentA     |.......student_num|
             |..................| memo
             |..................|
             |..................|
             |..................|
             |........nameA_heap|
             +------------------+
             |.........prev_size|
             |..............size|
studentB     |.......student_num|
             |..................| memo
             |..................|
             |..................|
             |..................|
             |........nameB_heap|
             +------------------+
```

real memory layout:

```assembly
0x6031e0:       0x0000000000000000      0x0000000000000000
0x6031f0:       0x0000000000000000      0x0000000000000000
0x603200:       0x0000000000000000      0x0000000000603220 # nameA_heap
0x603210:       0x0000000000000000      0x0000000000000031
0x603220:       0x0000000000000000      0x0000000000000000
0x603230:       0x0000000000000000      0x0000000000000000
0x603240:       0x0000000000000000      0x0000000000000041
0x603250:       0x0000000000000001      0x0000000000000000
0x603260:       0x0000000000000000      0x0000000000000000
0x603270:       0x0000000000000000      0x0000000000603290 # nameB_heap

# after one-byte overflow

0x6031e0:       0x0000000000000000      0x0000000000000000
0x6031f0:       0x0000000000000000      0x0000000000000000
0x603200:       0x0000000000000000      0x0000000000603278 # address of storing nameB_heap
0x603210:       0x0000000000000000      0x0000000000000031
0x603220:       0x0000000000000000      0x0000000000000000
0x603230:       0x0000000000000000      0x0000000000000000
0x603240:       0x0000000000000000      0x0000000000000041
0x603250:       0x0000000000000001      0x0000000000000000
0x603260:       0x0000000000000000      0x0000000000000000
0x603270:       0x0000000000000000      0x0000000000603290

```

### Second:

接著我們為 student A 命名，就可以 overwrite student B name heap 的 address，把 address 改成隨便一個 libc function 的 GOT entry 在這我是 leak `puts`，之後再用 `show name` 就可以 leak info

after overwrite:

```
0x6031e0:       0x0000000000000000      0x0000000000000000
0x6031f0:       0x0000000000000000      0x0000000000000000
0x603200:       0x0000000000000000      0x0000000000603278
0x603210:       0x0000000000000000      0x0000000000000031
0x603220:       0x0000000000000000      0x0000000000000000
0x603230:       0x0000000000000000      0x0000000000000000
0x603240:       0x0000000000000000      0x0000000000000041
0x603250:       0x0000000000000001      0x0000000000000000
0x603260:       0x0000000000000000      0x0000000000000000
0x603270:       0x0000000000000000      0x0000000000601fa0 # GOT entry of puts
```

### Third:

有 **libc base address** 之後，我們就可以拿到 **system address**，但是因為這題是 FULL RELRO，所以 GOT 不可以修改，因此，我們需要修改 stack 上的 return address

libc 裡面有一個 symbol - `environ` 裡面存著 stack address，所以重複 step first & second，來拿 stack address，之後算一下 offset 就可以知道 `main` 的 return address 的位置

這裡為什麼要用 `main`，因為 `f` 這個 function 只有兩種離開方式，一個是利用 `longjmp` 另一個是利用 `exit(0)`，所以我們必須要用到 `longjmp` 回到 `main`，再控制 eip

### Fourth:

在這步驟我們需要做兩件事，把 "sh" 寫上 memory (或是直接利用 libc 裡的 "sh")，把 `main` 的 return address 寫掉，偽造 system function call

因為我們需要 `longjmp` 讓程式跳回 `main`，在 add student 裡，他會檢查學生人數是不是超過 30 如果超過就會呼叫 `longjmp`，所以我把 "sh" 寫在 student_num 這個 global variable，這樣下次呼叫 add student 就會跳回 `main`，然後 return 開 shell

[Exploit code](https://github.com/Naetw/CTF-write-up/blob/master/SECCON-CTF-2016/jmper/ex.py)

