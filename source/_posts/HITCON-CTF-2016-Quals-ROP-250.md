---
title: '[HITCON CTF 2016 Quals] ROP 250'
author: bruce30262
tags:
  - Reverse
  - Ruby
  - HITCON CTF 2016
categories:
  - write-ups
  - ''
date: 2016-10-14 20:09:00
---
## Info  
> Category: Reverse
> Point: 250
> Solver: bruce30262 @ BambooFox   

## Analyzing
題目給了我們一個叫做 `rop.iseq` 的檔案
查過 file header 之後，發現是 [Ruby InstructionSequence](https://ilconnettivo.wordpress.com/2015/12/25/ruby-2-3-0-instructionsequence/) 的 binary 格式。

Ruby 在 2.3 版本中針對 InstructionSequence 的部分加入了一些新功能，例如 [load_from_binary 函式](http://ruby-doc.org/core-2.3.0/RubyVM/InstructionSequence.html#method-c-load_from_binary) 可以讓使用者從一個 binary 檔案當中 load 進 InstructionSequence，並做進一步的操作 (ex. 執行指令, 印出 disassemble 的內容......等)

```ruby de.rb
#!/usr/bin/env ruby
# read rop.iseq, dump InstructionSequence
f = open("rop.iseq", "rb")
a = f.read()
d = RubyVM::InstructionSequence.load_from_binary(a)
#d.eval #execute the instruction sequence
puts d.disasm # print out the disassemble result
```
上頭的 ruby script 就是一個從 binary 檔案當中 load 進 iseq 的例子。`d.eval` 可以讓我們執行這個 iseq:

<pre>
bruce30262@ubuntu:~/Desktop$ ruby ./de.rb 
AAAA
Invalid Key @_@
</pre>

看來跟其他 reverse 的題目差不多，一樣是讀入 user input 之後做一連串的檢查，然後印出檢查的結果。這題看起來是要想辦法找出 valid key，通過檢查之後讓程式將 flag 給 print 出來。

接下來 dump 出 disassemble 的結果觀察一下 ( 內容有點大，這裡只列出部分的結果，完整的 disassemble 結果可以看[這裡](https://gist.github.com/bruce30262/1e8fd1439f13e75cf72e0c265dd612de) )

```
== disasm: #<ISeq:<compiled>@<compiled>>================================
== catch table
| catch type: break  st: 0096 ed: 0102 sp: 0000 cont: 0102
| catch type: break  st: 0239 ed: 0245 sp: 0000 cont: 0245
|------------------------------------------------------------------------
local table (size: 3, argc: 0 [opts: 0, rest: -1, post: 0, block: -1, kw: -1@-1, kwrest: -1])
[ 3] k          [ 2] xs         
0000 trace            1                                               (   1)
0002 putself          
0003 putstring        "digest"
0005 opt_send_without_block <callinfo!mid:require, argc:1, FCALL|ARGS_SIMPLE>, <callcache>
0008 pop              
0009 trace            1                                               (   2)
0011 putself          
0012 putstring        "prime"
0014 opt_send_without_block <callinfo!mid:require, argc:1, FCALL|ARGS_SIMPLE>, <callcache>
....................一堆東西..........
```

瘋狂 google 之後發現一篇有用的[教學文](http://kgrz.io/2014/04/19/ruby-trace-leave-oh-my.html)，裡頭介紹了一些基礎的 ruby iseq reversing。例如以下的 iseq:

```
0000 trace            1                                               (   1)
0002 putself          
0003 putstring        "digest"
0005 opt_send_without_block <callinfo!mid:require, argc:1, FCALL|ARGS_SIMPLE>, <callcache>
```

其中 `trace 1` 代表著 "我遇到了一行 ruby code"，接下來往下看幾行，我們大概可以知道，程式將 "digest" 視為一個參數，並且呼叫了`require`，因此這行的 ruby code 應該就是在做 `require "digest"`

透過這樣子的 pattern ( 塞參數 --> call method ) 持續的 reverse 下去，我們其實就可以將整個程式的執行流程給還原回來。

此外，我們還可以利用 `ruby -r tracer de.rb` 這樣的執行方式，來讓 ruby 印出程式執行時的 trace。因為這題檢查 key 的方式是採取分段式的檢查，所以如果我們前半部的 key 有對的話，程式其實會執行到較多的指令，因此我們可以利用這樣子的方式(檢查 trace情形)來驗證我們的 key 有沒有解對 (類似 side channel attack)。

## Solution
首先是 key 格式的檢查。這部分比較簡單，可以整理成以下的 pseudo code:
```ruby
key = gets.chomp
key = key.split("-")
if (key.size == 5) and (key.all?)
    for k in key
        if not k =~ /^[0-9A-F]{4}$/
	        gg() # fail
        end
    end
else
    gg() # fail
end 

```
因此我們可以知道 key 的格式為 `XXXX-XXXX-XXXX-XXXX-XXXX`，並且每個 `X` 的範圍都位於 [0-9A-F] 之間。接下來要還原 key 的每一個部分。

第一個部分的檢查其實很簡單:
```
# key[0]
0111 getlocal_OP__WC__0 2
0113 putobject_OP_INT2FIX_O_0_C_ 
0114 opt_aref         <callinfo!mid:[], argc:1, ARGS_SIMPLE>, <callcache>

# key[0].to_i(16)
0117 putobject        16
0119 opt_send_without_block <callinfo!mid:to_i, argc:1, ARGS_SIMPLE>, <callcache>

# key[0].to_i(16) == 31337
0122 putobject        31337
0124 opt_eq           <callinfo!mid:==, argc:1, ARGS_SIMPLE>, <callcache>
```
所以就是 `key[0]` 的 hex value 要等於 31337，因此 `key[0]` = `"7A69"`

第二部分 ( `key[1]` ) 的檢查更簡單:
```
# key[1]
0136 getlocal_OP__WC__0 2
0138 putobject_OP_INT2FIX_O_1_C_ 
0139 opt_aref         <callinfo!mid:[], argc:1, ARGS_SIMPLE>, <callcache>

# key[1].reverse
0142 opt_send_without_block <callinfo!mid:reverse, argc:0, ARGS_SIMPLE>, <callcache>

# key[1].reverse == "FACE"
0145 putstring        "FACE"
0147 opt_eq           <callinfo!mid:==, argc:1, ARGS_SIMPLE>, <callcache>
```
`key[1].reverse == "FACE"`，因此 `key[1]` = `"ECAF"`

然後是第三部分 ( `key[2]` ) 的檢查:
```
# call f(217, key[2].to_i(16), 314159)
0160 putobject        217
0162 getlocal_OP__WC__0 2
0164 putobject        2
0166 opt_aref         <callinfo!mid:[], argc:1, ARGS_SIMPLE>, <callcache>
0169 putobject        16
0171 opt_send_without_block <callinfo!mid:to_i, argc:1, ARGS_SIMPLE>, <callcache>
0174 putobject        314159
0176 opt_send_without_block <callinfo!mid:f, argc:3, FCALL|ARGS_SIMPLE>, <callcache>

# f(217, key[2].to_i(16), 314159).to_s(28).upcase == "48D5"
0179 putobject        28
0181 opt_send_without_block <callinfo!mid:to_s, argc:1, ARGS_SIMPLE>, <callcache>
0184 opt_send_without_block <callinfo!mid:upcase, argc:0, ARGS_SIMPLE>, <callcache>
0187 putstring        "48D5"
0189 opt_eq           <callinfo!mid:==, argc:1, ARGS_SIMPLE>, <callcache>
0192 branchif         199
```
這邊開始變得比較複雜。首先程式會 call 函式`f(217, key[2].to_i(16), 314159)`，其回傳值的 **28 進位**要等於 48D5 ( 換算成 10 進位的話是 94449 )。
而 `f` 這個函式做的事情有點複雜，這邊就只列 pseudo code:
```ruby
def f(two17, key2, pi)
    ret = 1
    v2 = two17
    while key2 != 0
        if key2[0] == 1 # the first bit of current key2
            ret = (ret*v2)%pi
        end
        key2 = key2>>1
        v2 = (v2*v2)%pi
    end
    return ret
end
```
這部分就是硬 reverse 努力得把 code 給看懂。

有了演算法之後就可以用爆的方式將 `key[2]` 給爆出來 ( 0x0000 ~ 0xffff, 最多跑 65536 次)
```ruby crack_part3.rb
def f(two17, key2, pi)
    ret = 1
    v2 = two17
    while key2 != 0
        if key2[0] == 1 # the first bit of current key2
            ret = (ret*v2)%pi
        end
        key2 = key2>>1
        v2 = (v2*v2)%pi
    end
    return ret
end

for i in (0..0xffff)
    ret = f(217,i, 314159)
    if ret == 94449
        puts "got it!"
        puts i.to_s(16)
    end
end
```
跑完之後即可得知 `key[2]` = `"1BD2"`

接下來是第四部份 ( `key[3]` ) :
```
# key[3]
0201 getlocal_OP__WC__0 2
0203 putobject        3
0205 opt_aref         <callinfo!mid:[], argc:1, ARGS_SIMPLE>, <callcache>

# key[3].to_i(10).prime_division
0208 putobject        10
0210 opt_send_without_block <callinfo!mid:to_i, argc:1, ARGS_SIMPLE>, <callcache>
0213 opt_send_without_block <callinfo!mid:prime_division, argc:0, ARGS_SIMPLE>, <callcache>


# b = key[3].to_i(10).prime_division.map &:first
0216 putobject        :first
0218 send             <callinfo!mid:map, argc:0, ARGS_BLOCKARG>, <callcache>, nil

# b.sort == [53,97]
0222 opt_send_without_block <callinfo!mid:sort, argc:0, ARGS_SIMPLE>, <callcache>
0225 duparray         [53, 97]
0227 opt_eq           <callinfo!mid:==, argc:1, ARGS_SIMPLE>, <callcache>
```
這邊主要是困難在 `key[3].to_i(10).prime_division.map &:first` 這行，可以看到呼叫 `map` 時明明就有個 `:first` 參數，但是 `map` 的 argc 卻顯示為 `0` 。最後 google 到[這篇](http://qiita.com/yui-knk/items/f7ce1c3138ef44872d3b)才了解到原來還有 `XXX.map &:first` 這種寫法。

這邊 `prime_division` 是在做質因數分解，看到結果要等於 [53,97] 的時候其實就可以猜 `key[3]` = `53*97` = `5141` 了。原本 5141 做 prime_division 時會變成 `[ [53,1] , [97,1] ]`, 意即 `(53^1 * 97^1)`，不過因為 `&:first` 的關係，只會取到第一個元素，也就是 53 跟 97，符合 `key[3]` 的條件。雖然答案其實是 `(53^n * 97^m)`，不過考慮到數值最大只到 65536，因此符合條件的只有 `n=1, m=1` ，所以可以得知 `key[3]` = `5141`

到了這邊~~其實我已經沒力了~~我們已經知道這題的 valid key 為 `7A69-ECAF-1BD2-5141-XXXX` 。第五部分 ( `key[4]` ) 的檢查由於很複雜的關係 ( 用了一些很怪的語法 )，加上其實只剩下最後一個部分的 key 沒有解出來，所以這邊我直接採取暴力破解的方式來找出 key 的最後一部分 ( 反正最多也就跑 65536 次 =w= ):
```ruby crack_flag.rb
#!/usr/bin/env ruby

for i in (0..0xffff)
    key = "7A69-ECAF-1BD2-5141-%04X" % i
    cmd = "echo \"#{key}\" | ruby de.rb"
    puts cmd
    resp = `#{cmd}`
    if not resp.include?"Invalid"
        puts resp
        break
    end
end
```
放著讓它跑個 20 分鐘:

<pre>
........................
echo "7A69-ECAF-1BD2-5141-CA70" | ruby de.rb
echo "7A69-ECAF-1BD2-5141-CA71" | ruby de.rb
echo "7A69-ECAF-1BD2-5141-CA72" | ruby de.rb
Congratz! flag is hitcon{ROP = Ruby Obsecured Programming ^_&lt}
</pre>

拿到 flag 了 :P  ( 看來應該要從 0xffff 往下爆的，應該會更快 XD )

valid key: `7A69-ECAF-1BD2-5141-CA72`

flag: `hitcon{ROP = Ruby Obsecured Programming ^_<}`
