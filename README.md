
# THM-basiclevelctf-Writeup
https://tryhackme.com/room/basiclevelctf

The first step is to find out which ports are open.

```
nmap -sCV -vv [target_ip]
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
dirb http://[target_ip]
```
![dirb](images/dirb.png)

# Checking robots.txt
After checking **robots.txt**, we realized that there is a file named **secret.lst** thanks to robots.txt and it is most likely a wordlist.

![robots](images/robots.png)
![secretlst](images/secretlst.png)

# Research exploit for open port 22 or 80
Now we only have a wordlist and the ssh service is open. But we did not investigate whether the service running on port 80 has any vulnerability, let's start researching.
