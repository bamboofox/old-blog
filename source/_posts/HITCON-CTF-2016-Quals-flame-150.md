---
title: '[HITCON CTF 2016 Quals] flame 150'
author: bruce30262
tags:
  - PPC
  - PowerPC
  - qemu
  - Reverse
  - HITCON CTF 2016
categories:
  - write-ups
date: 2016-10-14 18:14:00
---
## Info  
> Category: PPC ( 個人覺得比較像 Reverse ) 
> Point: 150
> Solver: bruce30262 @ BambooFox   

## Analyzing
題目給了我們一隻 binary, 32 bit PowerPC ELF
這題運氣不錯，打 CTF 用的 docker image 裡面剛好有裝 `qemu-ppc-static`，加上這題剛好是一隻 static linked 的 binary, 不需要再額外裝 PPC 的 libc，因此透過以下 command 即可將 binary run 起來:

<pre>
# root @ 9c51322c8256 in /mnt/files/hitcon-ctf-2016-qual/flame [7:51:02] 
$ qemu-ppc-static ./flame
*************************************
*                                   *
*   HITCON CTF 2016 Flag Verifier   *
*                                   *
*************************************
Check your flag before submission: AAAA
Your flag is incorrect :(
</pre>

可以看到程式會要求我們輸入 flag，然後對我們的 flag 做驗證，之後吐出驗證結果。

這題靜態分析方面是直接丟 IDA Pro，至於動態分析的部分，則是利用 `qemu-ppc-static -g 10001 ./flame` 指令先開一個 gdb connection，之後搭配 gdb-multiarch + target remote 來 debug 程式。

那麼開始 reverse。這題驗證 flag 的演算法其實沒有很複雜，可以整理成以下的 pseudo code:
```c
int main()
{
    scanf("%s", flag); // lol buffer overflow
    if( strlen(flag) == 35)
    {
        srandom(0x1e61);
        int i;
        for (i = 0 ; i < 35 ; i++)
        {
            r = rand();
            check[i] = flag[i] ^ (r & 0xfff);
        }
        for (i = 0 ; i < 35 ; i++)
        {
            if ( check[i] != secret[i] )
            {
                fail();
            }
        }
        success();
    }
    else
    {
        fail();
    }
}
```
比較麻煩的地方就是 `check[i] = flag[i] ^ (r & 0xfff);` 這行，其實際的 PPC assembly 長這樣:
```
// r = rand();
bl        rand
mr        r9, r3
// r = r & 0xfff
clrlwi    r10, r9, 20 <-- clear the high-order 20 bits
lwz       r9, 0x18(r31)
slwi      r9, r9, 2
addi      r8, r31, 0x1A0
add       r9, r8, r9
addi      r9, r9, -0x180
stw       r10, 0(r9)
lwz       r9, 0x18(r31)
slwi      r9, r9, 2
addi      r10, r31, 0x1A0
add       r9, r10, r9
addi      r9, r9, -0x180
lwz       r9, 0(r9)
mr        r8, r9
// c = flag[i]
addi      r10, r31, 0x138
lwz       r9, 0x18(r31)
add       r9, r10, r9
lbz       r9, 0(r9)
// check[i] = c ^ r
xor       r9, r8, r9
mr        r10, r9
lwz       r9, 0x18(r31)
slwi      r9, r9, 2
addi      r8, r31, 0x1A0
add       r9, r8, r9
addi      r9, r9, -0x180
stw       r10, 0(r9)
// i++ (loop counter)
lwz       r9, 0x18(r31)
addi      r9, r9, 1
stw       r9, 0x18(r31)
```
不過只要花點時間 + 瘋狂 google 應該不難搞懂 

## Solution
總而言之程式會先檢查我們的 flag 是不是 35 個字元，如果是的話就會針對每一個字元做一些運算，然後將結果存入 `check` 這個 buffer 裡面。之後會檢查 `check` buffer 與 `secret` buffer 的內容是否相同，是的話即通過檢查。

`secret` buffer 的內容可以透過 debugger dump 出來:

<pre>
0xf6fff86c:     0x00000cfe      0x00000859      0x0000095d      0x00000871
0xf6fff87c:     0x0000040d      0x00000006      0x00000ade      0x00000fa8
0xf6fff88c:     0x00000561      0x000009da      0x00000878      0x00000682
0xf6fff89c:     0x00000fa9      0x00000f5f      0x0000025e      0x00000db0
0xf6fff8ac:     0x00000fbf      0x00000bc6      0x00000d38      0x0000095d
0xf6fff8bc:     0x00000d09      0x000007ed      0x00000307      0x000001c0
0xf6fff8cc:     0x00000399      0x00000956      0x00000a45      0x00000292
0xf6fff8dc:     0x00000c8a      0x0000092f      0x0000004a      0x00000964
0xf6fff8ec:     0x00000194      0x000009da      0x0000011f 
</pre>

之後就是寫些程式將 flag 給 recover 回來:
```ruby sol.rb
#!/usr/bin/env ruby

resp = `./test`.split("\n")
seed = []
ans =[0x00000cfe, 0x00000859, 0x0000095d, 0x00000871, 0x0000040d,0x00000006,0x00000ade, 0x00000fa8, 0x00000561,  0x000009da , 0x00000878, 0x00000682, 0x00000fa9 , 0x00000f5f, 0x0000025e, 0x00000db0, 0x00000fbf, 0x00000bc6 , 0x00000d38 , 0x0000095d, 0x00000d09, 0x000007ed , 0x00000307, 0x000001c0, 0x00000399, 0x00000956 , 0x00000a45 , 0x00000292, 0x00000c8a,0x0000092f , 0x0000004a , 0x00000964, 0x00000194,  0x000009da, 0x0000011f]
 
for s in resp
    seed << (s.to_i(16) & 0xfff)
end

flag = ""

for a,b in seed.zip(ans)
    flag += (a^b).chr
end

puts flag
```
其中 test 是個先將 random value 給 gen 好的 C 程式
```c test.c
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    int i = 0;
    srand(0x1e61);
    for(i = 0 ; i < 35 ; i++)
    {
        printf("0x%x\n", rand());
    }
    return 0;
}
```

執行結果:

<pre>
# root @ 9c51322c8256 in /mnt/files/hitcon-ctf-2016-qual/flame [8:42:43] C:126
$ ruby ./sol.rb 
hitcon{P0W3rPc_a223M8Ly_12_s0_345y}
</pre>

flag: `hitcon{P0W3rPc_a223M8Ly_12_s0_345y}`
