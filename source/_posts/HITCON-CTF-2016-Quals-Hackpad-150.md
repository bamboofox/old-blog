---
title: '[HITCON CTF 2016 Quals] Hackpad 150'
author: bruce30262
tags:
  - Crypto
  - Forensic
  - padding oracle attack
  - HITCON CTF 2016
categories:
  - write-ups
date: 2016-10-14 23:01:00
---
## Info  
> Category: Crypto & Forensics
> Point: 150
> Solver: bruce30262 @ BambooFox
> 這題其實是從中間接下去解的
> 感謝其他隊友們先做出前面的的部分

## Analyzing
題目給了個 pcap 檔，要我們找出裡面的 secret。經過分析後可以從裡面抓出一些重要的資訊:

首先是 secret 的密文:
<pre>
encrypt(secret):
msg=
3ed2e01c1d1248125c67ac637384a22d
997d9369c74c82abba4cc3b1bfc65f02 
6c957ff0feef61b161cfe3373c2d9b90
5639aa3688659566d9acc93bb72080f7
e5ebd643808a0e50e1fc3d16246afcf6
88dfedf02ad4ae84fd92c5c53bbd98f0
8b21d838a3261874c4ee3ce8fbcb9662
8d5706499dd985ec0c13573eeee03766
f7010a867edfed92c33233b17a9730eb
4a82a6db51fa6124bfc48ef99d669e21
740d12656f597e691bbcbaa67abe1a09
f02afc37140b167533c7536ab2ecd4ed
37572fc9154d23aa7d8c92b84b774702
632ed2737a569e4dfbe01338fcbb2a77
ddd6990ce169bb4f48e1ca96d30eced2
3b6fe5b875ca6481056848be0fbc26bc
bffdfe966da4221103408f459ec1ef12
c72068bc1b96df045d3fa12cc2a9dcd1
62ffdf876b3bc3a3ed2373559bcbe3f4
70a8c695bf54796bfe471cd34b463e98
76212df912deef882b657954d7dada47
</pre>

這邊刻意將密文以 32 字元為單位做分割，等等會用到。

之後是跟 decrypt message 相關的一些資訊:

<pre>
msg=00000000000000000000000000000000997d9369c74c82abba4cc3b1bfc65f02
md5(decrypt(msg)) = aa85a4e0adbd34c287af2d20da4453c9

msg=0000000000000000000000000000d903997d9369c74c82abba4cc3b1bfc65f02
md5(decrypt(msg)) = 9f5b543c64d3e384078fdd8cf4b2ce6d

msg=00000000000000000000000000efd802997d9369c74c82abba4cc3b1bfc65f02
md5(decrypt(msg)) = c68dda2cc0d9907bc7252b53a447b2ce

msg=00000000000000000000000007e8df05997d9369c74c82abba4cc3b1bfc65f02
md5(decrypt(msg)) = 650713f94eae0ecdfa4e527745dd2591
................................................
................................................
msg=0000ce71616536683d0ed00c0de2d50f997d9369c74c82abba4cc3b1bfc65f02
md5(decrypt(msg)) = 6d09e40852ecf180281d504b7718d12d

msg=00b3cf70606437693c0fd10d0ce3d40e997d9369c74c82abba4cc3b1bfc65f02
md5(decrypt(msg)) = f1290186a5d0b1ceab27f4e77c0c5d68

msg=67acd06f7f7b28762310ce1213fccb11997d9369c74c82abba4cc3b1bfc65f02
md5(decrypt(msg)) = d41d8cd98f00b204e9800998ecf8427e
................................................
................................................
</pre>

這邊注意 `00000000000000000000000000000000997d9369c74c82abba4cc3b1bfc65f02` 的後半部，其實跟密文中的第二行是一模一樣的。透過一些觀察，可以知道有人不斷的嘗試將一串密文送給 server 進行解密的動作，而且會根據 server 的回覆來更新要解密的密文。

因為對 crypto 沒啥 sense，所以一開始就只是盯著這一連串的解密訊息，想說看看有沒有什麼規律可以幫助解密。結果當然是沒什麼用，直到發現 server 那邊回傳的 response 其實有很多的 500 和 403，**"只有特定的密文才會解密成功，否則會回傳解密失敗"** 這點讓我想到這會不會是 [padding oracle attack](https://en.wikipedia.org/wiki/Padding_oracle_attack)

結果 google 之後發現這完全就是 padding oracle attack 啊 ! 所以這題才叫做 Hackpad，因為 "Hack padding" 嘛 XD

## Solution
有了方向之後其實就蠻容易解的，畢竟所有的攻擊密文已經有人幫我們做好，全放在封包裡了。所以根據這篇 [MSLC 的 writeup](http://mslc.ctf.su/wp/codegate-ctf-2011-crypto-400/)，我們其實可以直接解密原本的 secret:

以密文 `997d9369c74c82abba4cc3b1bfc65f02`(C1) 來說，其攻擊密文為 `67acd06f7f7b28762310ce1213fccb11`，padding 為 `10101010101010101010101010101010`，因此算出 `AES_Decrypt(C1)` = `67acd06f7f7b28762310ce1213fccb11 ^ 10101010101010101010101010101010`

之後因為 `AES_Decrypt(C1)` = `P1(明文) ^ C0(前一個密文)`，因此可以得出 `P1` = `AES_Decrypt(C1) ^ C0`，其中 `C0` = `3ed2e01c1d1248125c67ac637384a22d`(前一個密文)

按照這樣的方式就可以將 secret 給還原回來:
```python ppp.py
#!/usr/bin/env python
# -*- coding: utf-8 -*-

import subprocess
import sys

def myexec(cmd):
    return subprocess.check_output(cmd, shell=True)

# "cat ./ggg": print out all the last attacker ciphertext

resp = myexec("cat ./ggg").split("\n")
del resp[-1]

temp = []
for i, c in enumerate(resp):
    if i == 0: # first line is encrypt(secret), ignore
        continue
    d = c.split("=")[1].strip()
    assert len(d) == 64
    temp.append(d)

last_c = []
enc = []
for c in temp:
    last_c.append(c[0:32])
    enc.append(c[32::])

enc.insert(0, "3ed2e01c1d1248125c67ac637384a22d")

def fix_len(s):
    if len(s) % 2 == 1:
        s = "0"+s
    assert len(s) == 32
    return s

cnt = 0
plain = ""
for c in last_c:
    c = c.decode('hex')
    pad = "10101010101010101010101010101010".decode('hex')
    s = 0
    for c1, c2 in zip(pad, c):
        s |= ord(c1)^ord(c2)
        s<<=8
    sss = hex(s>>8)[2:-1:]
    sss = fix_len(sss)

    s = 0
    sss = sss.decode('hex')
    eee = enc[cnt].decode('hex')
    for c1, c2 in zip(eee, sss):
        s |= ord(c1)^ord(c2)
        s<<=8
    f = hex(s>>8)[2:-1:]
    f = fix_len(f)

    plain += f.decode('hex')
    cnt += 1

print plain
```

先利用 strings 和 grep 將所有的攻擊密文先存進 `ggg` 這個檔案裡面，之後執行 `ppp.py`，即可得到明文:
<pre>
In cryptography, a padding oracle attack is an attack which is performed using the padding of a cryptographic message.
hitcon{H4cked by a de1ici0us pudding '3'}
In cryptography, variable-length plaintext messages often have to be padded (expanded) to be compatible with the underlying cryptographic primitive.
</pre>

flag: `hitcon{H4cked by a de1ici0us pudding '3'}`
