title: '[MMA CTF 2nd 2016] Make a Palindrome 50'
tags:
  - MMA CTF 2nd 2016
  - ppc
categories:
  - write-ups
author: 0Alien0
date: 2016-09-05 16:18:00
---
# [MMA CTF 2nd 2016] Make a Palindrome 50

> Category: ppc
> Point: 50
> Solver: 0Alien0 @ BambooFox

## Make a Palindrome

這題分兩個階段

只要答對第一題就可以拿到第一階段的 flag

答對剩下的題目則可以拿到第二階段的 flag

題目是他給你好幾個單字要你拼成回文字

b bba ab cc -> ab b cc bba 也就是 abbccbba

我想說先用暴力解解看(畢竟這只是 warm up 題)

然後就過了O_O(發現最大也才 10 個字 3628800 種可能而已 一塊蛋糕)

### 使用工具 :

pwn -> 連線

itertools -> 產生所有可能

### 解題流程 :

產生所有可能的字串 -> 檢查是不是回文 -> 答案

```python
from pwn import *
from itertools import *
def isPalindrome(s):
    for i in range(len(s)/2):
        if s[i] != s[len(s)-1-i]:
            return False
    return True

ip = "ppc1.chal.ctf.westerns.tokyo"
port = 31111

s = remote(ip,port)
print s.recv()
print "================"
for i in range(30):
    inp = ""
    while True:
        inp = s.recv()
        if inp.find("Input:") != -1:
            break
    print inp
    inp = inp[inp.find("Input:")+7:inp.find("Answer")].strip()
    L = inp.split()
    num = int(L[0])
    L.remove(L[0])
    #print num,L
    for j in permutations(L,num):
        if isPalindrome("".join(j)):
            s.sendline(" ".join(j))
            #print " ".join(j)
            break

s.interactive()

```