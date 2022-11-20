# Challenge #1 - Web Server Compromise.md

---

## Description

A company’s web server has been breached through their website. Our team arrived just in time to take a forensic image of the running system and its memory for further analysis. The files:

- [System Image](https://mega.co.nz/#!0FY2jC6C!IrWGIEicYrlodQnfttXLhbCFD551plWigzd097ue25s)
- [System Memory](https://mega.co.nz/#!1UpjkTab!RP_QeooLaxA7bixLxkHLIqhWKfQ9G_0M58NSUchRn68)
- [Hashes](https://mega.co.nz/#!FFZHBZxI!7vGrnQzN4ZK_XwcKBu8mQKzIKcdE7tM3rQ_zTqJQ6-U)
- [Passwords](https://mega.nz/file/ZRBlyITI#HcnwqU3DgSHbsSoSlUGxgMwzFexLSk5sZn6oXMd4PVA)

To successfully solve this challenge, a report with answers to the tasks below is required:
1. What type of attacks has been performed on the box?
2. How many users has the attacker(s) added to the box, and how were they added?
3. What leftovers (files, tools, info, etc) did the attacker(s) leave behind? (assume our team arrived in time and the attacker(s) couldn't clean and cover their tracks)
4. What software has been installed on the box, and were they installed by the attacker(s) or not?
5. Using memory forensics, can you identify the type of shellcode used?
6. What is the timeline analysis for all events that happened on the box?
7. What is your hypothesis for the case, and what is your approach in solving it?
8. Is there anything else you would like to add?

Bonus Question: 

- What are the directories and files, that have been added by the attacker(s)? List all with proof.

---

## Tools to be used

1. Arsenal Image Mounter (Free Version)
2. Velociraptor
3. YARA

---

## 1. Mounting the disk image

To mount the disk image, we can make use or **Arsenal Image Mounter**. The steps are quite trivial so I won't document it in details here.

![image](https://user-images.githubusercontent.com/38507703/202907088-a078d3df-929a-48f7-8d74-831dfe13acd1.png)

As shown, the image is mounted in `E:` drive. Briefly checking the root, we can see that `xampp` exists:

![image](https://user-images.githubusercontent.com/38507703/202907199-f8863b3e-cc98-4a76-b62e-5cf756ce9773.png)

> XAMPP is an easy to install Apache distribution containing MariaDB, PHP, and Perl.

---

## 2. Hunt for webshell

One of the most common attack on webserver to gain initial access would be using **webshell**. We may try to use **YARA** with the webshell signatures in [Neo23x0-thor-webshells.yar](https://github.com/Neo23x0/signature-base/blob/master/yara/thor-webshells.yar).

```
yara64.exe ..\Neo23x0-Signatures\yara\thor-webshells.yar -r E:\xampp
```

![image](https://user-images.githubusercontent.com/38507703/202908649-026a2992-1ae8-4650-9c4f-712354369835.png)

As shown, there are multiple webshell signature matches pointingto the file `E:\xampp\htdocs\DVWA\c99.php`. Let's get the file hash using PowerShell cmdlet:

```powershell
Get-FileHash -Algorithm MD5 E:\xampp\htdocs\DVWA\c99.php; Get-FileHash -Algorithm SHA1 E:\xampp\htdocs\DVWA\c99.php; Get-FileHash -Algorithm SHA256 E:\xampp\htdocs\DVWA\c99.php
```

![image](https://user-images.githubusercontent.com/38507703/202908788-baf418f5-ee03-4d4b-b6ee-121de375da36.png)

- 86A5679E047B1629832A4CBD89D5EBB7
- 70767616174E17D7B926272A6C9E13B174E9F897
- 4320D95CC2FE61E0B862756F8C4FFB251C7D1391E2F6841887C3DC765BA0369C

We can also get time information with `Get-ChildItem`:

```powershell
Get-ChildItem E:\xampp\htdocs\DVWA\c99.php | Select *Time*
```

![image](https://user-images.githubusercontent.com/38507703/202908936-b9cedd78-eb1c-4605-8194-57302b77b862.png)

- We may assume the webshell was written on or before **3 Sept 2015 15:20:45**.

---
