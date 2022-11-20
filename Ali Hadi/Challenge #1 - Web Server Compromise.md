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
4. PowerShell
5. Volatility 2

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

- We may assume the webshell was written on or before **3 Sept 2015 15:20:45 (+0800)** / **3 Sept 2015 07:20:45 UTC**.

---

## 3. Web logs collection

Since this is a web server, we should collect the web access logs and investigate. For **xampp**, the access logs locate in:

- `E:\xampp\apache\logs`

![image](https://user-images.githubusercontent.com/38507703/202909089-883ae834-e5bd-4e6a-b471-c5014374b68b.png)

We can use [apache-log-to-csv](https://github.com/isonet/apache-log-to-csv) (code in Python 2) (required module apache-log, parser, argparse, csv) to parse the access log to CSV format.

```python2
import csv
import apache_log_parser
import argparse


def main(**kwargs):

    print('Converting, please wait...')

    line_parser = apache_log_parser.make_parser(kwargs['format'])
    header = True

    with open(kwargs['input'], 'rb') as inFile, open(kwargs['output'], 'w') as outFile:

        lines = inFile.readlines()
        writer = csv.writer(outFile, delimiter=',')

        for line in lines:
            try:
                log_line_data = line_parser(line)
            except apache_log_parser.LineDoesntMatchException as ex:
                print('The format specified does not match the log file. Aborting...')
                print('Line: ' + ex.log_line + 'RegEx: ' + ex.regex)
                exit()

            if header:
                writer.writerow(list(log_line_data.keys()))
                header = False
            else:
                writer.writerow(list(log_line_data.values()))

    print('Conversion finished.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Convert Apache logs to csv', version='%(prog)s 1.0')
    parser.add_argument('format', type=str, help='Apache log format (see http://httpd.apache.org/docs/2.2/logs.html)')
    parser.add_argument('input', type=str, help='Input log file ex. /var/log/apache/access.log')
    parser.add_argument('output', type=str, help='Output csv file ex. ~/accesslog.csv')
    args = parser.parse_args()
    main(**vars(args))
```

To convert:

```
pip2 install apache_log_parser argparse
python2 ~/parsers/apache-to-csv.py "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" access.log access.csv
```

As we know the suspicious webshell **c99.php**, check the http request containing `c99.php` around **3 Sept 2015 07:20:45 UTC**.

![image](https://user-images.githubusercontent.com/38507703/202911493-917560a4-a656-45bc-8bd8-51f809f706d8.png)

As shown, the attacker at **192.168.56.102** accessed the webshell from **3 Sept 2015 07:19:32 - 07:21:37 UTC**.

Pivoting this information, it would be interesting to know the activities performed by **192.168.56.102**:

![image](https://user-images.githubusercontent.com/38507703/202911701-364b6ed0-7b92-412e-af06-c02003b16fa5.png)

![image](https://user-images.githubusercontent.com/38507703/202911766-26a86162-7842-45af-99b6-8c1baae83abe.png)

![image](https://user-images.githubusercontent.com/38507703/202911810-e767ea8e-f129-4118-b584-95084cafaa6e.png)

- In so, the earliest attack on **3 Sept 2015** was at **3 Sept 2015 06:20:00 UTC**
- XSS at `/dvwa/vulnerabilities/xss_r/` was observed
- SQLi at `/dvwa/vulnerabilities/sqli/` was observed
- Webshell was observed at (written via SQLi) `/xampp/htdocs/tmpudvfh.php`, `/htdocs/tmpudvfh.php`, `/tmpudvfh.php`, `/dvwa/hackable/uploads/phpshell.php` (probably uploaded via `POST /dvwa/vulnerabilities/upload/`) and `/dvwa/c99.php`

---

## 4. Memory Forensics

Here we will use **Volatility 2** as our memory forensics tool.

```
vol2 imageinfo -f memdump.mem
vol2 -f memdump.mem --profile=Win2008SP1x86 cmdscan
```

Check command line history using `cmdscan`:

```
vol2 -f memdump.mem --profile=Win2008SP1x86 cmdscan
```

![image](https://user-images.githubusercontent.com/38507703/202913137-db60f280-523a-4165-b5b6-eb52a67e4da9.png)

As shown, the attacker ran some commands for:

1. Add new users `user1`
2. Add `user1` into the user group `Remote Desktop Users`
3. Use `netsh firewall` to enable remote desktop

Inspect the Process Tree using `pstree`:

```
vol2 -f memdump.mem --profile=Win2008SP1x86 pstree
```

![image](https://user-images.githubusercontent.com/38507703/202913270-a4d81782-55e8-4ff6-9fb6-bd39a39bd9cd.png)

- No abnormal Parent-Child processes

