---
title: '[33C3 CTF 2016] The 0x90s called 150'
author: bruce30262
tags:
  - pwn
  - loca root
  - 33C3 CTF 2016
categories:
  - write-ups
date: 2016-12-31 08:36:00
---
## Info  
> Category: pwn
> Point: 150
> Author: bruce30262 @ BambooFox

## Analyzing
首先我們會需要到一個網頁來"啟動"我們的 challenge session。啟動後網頁會告訴我們 port 要連多少 ( IP 則是跟 web service 同一個 IP )，並告訴我們帳號密碼。一個 session 的連線時間為 5 分鐘。

nc 連過去並登入遠端機器之後，我們會發現這是一個 [Slackware Linux](http://www.slackware.com/):
```
$ nc 78.46.224.70 2323

Welcome to Linux 0.99pl12.

slack login: challenge
Password:challenge

Linux 0.99pl12. (Posix).
No mail.
slack:~$ uname -a
Linux slack 0.99.12 #6 Sun Aug 8 16:02:35 CDT 1993 i586
```
隨意逛了一下，會發現在根目錄有個 flag.txt:
```
slack:/$ ls -al /flag.txt
-r--------   1 root     root           36 Dec 27  1916 /flag.txt
```

看來我們需要一個 local root 的 exploit 來解這題


## Exploit
強大的 google 使得我們很快就找到了 slackware linux 0.99 local root exploit 的 [PoC](https://github.com/HackerFantastic/Public/blob/master/exploits/prdelka-vs-GNU-lpr.c)。接下來只要想辦法把 PoC 傳到遠端機器上，然後編譯執行 exploit 即可。

問題是這題要傳 PoC 很麻煩，因為遠端機器根本沒有 tool 可以幫助我們下載檔案 --- 沒有 wget，沒有 curl，甚至連 nc 都沒有 ! 然後上面的 vi 編輯器難用到掉渣 ! 最後決定使用 `cat <<'EOF' >> test.c` + 複製貼上的方式將 exploit 寫入 test.c 裡頭

之後只要編譯執行 local root 的 exploit，即可拿到 root 權限並得到 flag:
```
slack:~$ gcc -o test test.c
slack:~$ ./test
[ Slackware linux 1.01 /usr/bin/lpr local root exploit
# id
id
uid=405(challenge) gid=1(other) euid=0(root) egid=18(lp)
# cat /flag.txt
cat /flag.txt
33C3_Th3_0x90s_w3r3_pre3tty_4w3s0m3
```

flag: `33C3_Th3_0x90s_w3r3_pre3tty_4w3s0m3`


