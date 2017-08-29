---
title: '[SECCON CTF 2016 Quals] Cheer_msg 100'
author: Naetw
tags:
  - pwn
  - SECCON CTF 2016
  - stack overflow
  - ROP
categories:
  - write-ups
date: 2016-12-12 08:24:00
---

## Info
> Category: pwn
> Point: 100
> Solver: Naetw @ BambooFox

## Analyzing

32 bit ELF, Partial RELRO, 有 canary & NX, 沒有 PIE

程式小小的，比較少見的部分是 `alloca` 的部分，不同於平常的 `malloc`，`alloca` 是從 caller 的 stack frame 上分配記憶體，在 function call 結束時，回收記憶體。


<!-- more -->

main:

![main](https://i.imgur.com/HVWlCzl.png)

因為 `alloca`，main 裡有一行指令是 `sub esp, eax`，這個 eax 的值會是根據輸入的 message length 並做一些處理，所以想法是讓 eax 為負數，`sub esp, eax` 指令做完後，esp 的 address 高於 ebp，這樣在 call message 時，**因為 message function 的 stack frame 跟 main 的 stack frame 重疊**，就可以用 overflow 來 overwrite return address。

來看一下 stack frame 的變化:

```
         +------------------+ low address
origin   |..................| <- esp 
         |..................|
         |..................|
         |..................|
         |..................|
         |..................|
         |......previous ebp| <- ebp
         |....return address| 
         +------------------+ high address
```

after `sub esp, eax`:

```
         +------------------+ low address
new      |..................|  
         |..................|
         |..................|
         |..................|
         |..................|
         |..................|
         |......previous ebp| <- ebp
         |....return address|
         |..................|
         |..................|
         |..................|
         |..................|
         |..................| <- esp
         +------------------+ high address
```

message:

![message](https://i.imgur.com/W7cpuzP.png)

雖然因為輸入的 length 是負數，第一個 `getnline` 無法輸入，但是主要利用的是 **stack frame 的重疊**，所以要寫入的地方就著重在 local variable `v3` 上

## Exploit

找到漏洞後，我們已經能利用 overwrite ret address 來控制 eip，不過我們還差 libc information

因此第一步是 **leak libc function address**，計算 `v3` 的位置與 main ret address 的 offset，因為是 32 bits，我們疊一下 fake function call，利用 `printf` 來 leak info 後，return 回 main

之後再做一次差不多的事，只是這次的 fake function call 是 call `system('sh')`

[Exploit code](https://github.com/Naetw/CTF-write-up/blob/master/SECCON-CTF-2016/cheer_msg/ex.py)

