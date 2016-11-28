title: '[Juniors CTF 2016] Gladly the cross I''d bear 500'
author: 'bananaapple,0Alien0'
tags:
  - PPC
  - Juniors CTF 2016
categories:
  - write-ups
date: 2016-11-28 14:36:00
---
## Info  
> Category: ppc
> Point: 500
> Author: OAlienO @ BambooFox

## Analysis

就是解 hamming(15,11)
(15,11) 就是將 11 bits 的原始資料
加上 4 bits 的 parity
變成 15 bits 加了檢查碼的資料

題目要解的是 block data
也就是 bits 變成 bytes
上面的解釋就變成
(15,11) 就是將 11 bytes 的原始資料
加上 4 bytes 的 parity
變成 15 bytes 加了檢查碼的資料

看圖片比較清楚

![hamming code](/img/hammingcode.png)

## Solutions

他給你一個檔案
就照著 Hamming Code 的定義
把他修補回來
就變回正常的照片檔案了

```python
from __future__ import division

def bits(f):
    bytes = (ord(b) for b in f.read())
    array = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    now = 0
    for b in bytes:
        array[now] = b
        if now == 14:
            yield array
        now = (now+1)%15

answer = ""

for b in bits(open('image_with_flag_defect.jpg.hamming', 'r')):
    ans = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    multiply = 1
    for i in xrange(8):
        parity = [0,0,0,0]
        for j in xrange(4):
            for k in xrange(1,16):
                if k&(1<<j):
                    parity[j] ^= b[k-1]%2
        if parity[0] or parity[1] or parity[2] or parity[3]:
            b[parity[0]*1+parity[1]*2+parity[2]*4+parity[3]*8-1] ^= 1
        for j in xrange(1,16):
            ans[j-1] += multiply*(b[j-1]%2)
            b[j-1] //= 2
        multiply *= 2
    for i in xrange(1,16):
        if i != 1 and i != 2 and i != 4 and i != 8:
            answer += chr(ans[i-1])

with open("flag","w") as f:
    f.write(answer)
```

## 參考資料 ( References )

[https://oalieno.github.io/Hamming-Code/](https://oalieno.github.io/Hamming-Code/)