# Teaching-HEIGVD-SRX-2019-Laboratoire-IDS

**ATTENTION : Commencez par créer un Fork de ce repo et travaillez sur votre fork.**

Clonez le repo sur votre machine. Vous retrouverez notamment dans ce repo le ficher `Dockerfile` indispensable pour [l'ajout des conteneurs et configuration du réseau](https://github.com/arubinst/Teaching-HEIGVD-SRX-2019-Labo-Firewall#ajout-des-conteneurs-et-configuration-du-réseau).

Vous pouvez répondre aux questions en modifiant directement votre clone du README.md ou avec un fichier pdf que vous pourrez uploader sur votre fork.

**Le rendu consiste simplement à compléter toutes les parties marquées avec la mention "LIVRABLE". Le rendu doit se faire par une "pull request". Envoyer également le hash du dernier commit et votre username GitHub par email au professeur et à l'assistant**

## Table de matières

[Introduction](https://github.com/arubinst/Teaching-HEIGVD-SRX-2019-Labo-Firewall#introduction)

[Echéance](https://github.com/arubinst/Teaching-HEIGVD-SRX-2019-Labo-Firewall#echéance)


## Introduction

Dans ce travail de laboratoire, vous allez explorer un système de detection contre les intrusions (IDS) dont l'utilisation es très répandue grace au fait qu'il est gratuit et open source. Il s'appelle [Snort](https://www.snort.org). Il existe des versions de Snort pour Linux et pour Windows.

### Les systèmes de detection d'intrusion

Un IDS peut "écouter" tout le traffic de la partie du réseau où il est installé. Sur la base d'une liste de règles, il déclenche des actions sur des paquets qui correspondent à la description de la règle.

Un example de règle pourrait être, en language commun : "tous les paquets envoyés par le port http à un serveur web dans le réseau, qui contiennent le string 'cmd.exe'". En on peut trouver des règles très similaires dans les règles par défaut de Snort. Elles permettent de détecter, par exemple, si un attaquant essaie d'executer un shell de commandes sur un serveur Web tournant sur Windows. On verra plus tard à quoi ressemblent ces règles.

Snort est un IDS très puissant. Il est gratuit pour l'utilisation personnelle et en entreprise, où il est très utilisé aussi pour la simple raison qu'il est l'un des plus efficaces systèmes IDS.

Snort peut être exécuté comme un logiciel indépendant sur une machine ou comme un service qui tourne après chaque démarrage. Si vous voulez qu'il protège votre réseau, il faudra l'installer "in-line" avec votre connexion Internet. 

Par exemple, pour une petite entreprise avec un accès Internet avec un modem simple et un switch interconnectant une dizaine d'ordinateurs de bureau, il faudra utiliser une nouvelle machine executant Snort et placée entre le modem et le switch. 

## Echéance 

Ce travail devra être rendu le dimanche après la fin de la 2ème séance de laboratoire, soit au plus tard, **le 31 mars 2019, à 23h.**


## Ecriture de règles

Snort permet l'écriture de règles qui décrivent des tentatives de exploitation de vulnérabilités bien connues. Les règles Snot prennent en charge à la fois, l'analyse de protocoles et la recherche et identification de contenu.

Il y a deux principes de base à respecter :

* Une règle doivent être entièrement contenue dans une seule ligne
* Les règles sont divisées en deux sections logiques : (1) l'entête et (2) les options.

L'entête de la règle contient l'action de la règle, le protocole, les adresses source et destination, et les ports source et destination.

L'option contient des messages d'alerte et de l'information concernant les parties du paquet dont le contenu doit être analysé. Par exemple:

```
alert tcp any any -> 192.168.1.0/24 111 (content:"|00 01 86 a5|"; msg: "mountd access";)
```

Cette règle décrit une alerte générée quand Snort trouve un paquet avec tous les attributs suivants :

* C'est un paquet TCP
* Emis depuis n'importe quelle adresse et depuis n'importe quel port
* A destination du réseau identifié par l'adresse 192.168.1.0/24 sur le port 111

Le text jusqu'au premier parenthèse est l'entête de la règle. 

```
alert tcp any any -> 192.168.1.0/24 111
```

La partie entre parenthèses sont les options de la règle:

```
(content:"|00 01 86 a5|"; msg: "mountd access";)
```

Les options peuvent apparaître une ou plusieurs fois. Par exemple :

```
alert tcp any any -> any 21 (content:"site exec"; content:"%"; msg:"site
exec buffer overflow attempt";)
```

La clé "content" apparait deux fois parce que les deux strings qui doivent être détectés n'apparaissent pas concaténés dans le paquet mais à des endroits différents. Pour que la règle soit déclenchée, il faut que le paquet contienne **les deux strings** "site exec" et "%". 

Les éléments dans les options d'une règle sont traitées comme un AND logique. La liste complète de règles sont traitées comme une succession de OR.

## Informations de base pour le rèbles

### Actions :

```
alert tcp any any -> any any (msg:"My Name!"; content:"Skon";sid:1000001;rev:1;)
```

L'entête contient l'information qui décrit le "qui", le "où" et le "quoi" du paquet. Ça décrit aussi ce qui doit arriver quand un paquet correspond à tous contenus dans la règle.

Le premier champ dans le règle c'est l'action. L'action dit à Snort ce qui doit être fait quand il trouve un paquet qui correspond à la règle. Il y a six actions :

* alert - générer une alerte et écrire le paquet dans le journal
* log - écrire le paquet dans le journal
* pass - ignorer le paquet
* drop - bloquer le paquet et l'ajouter au journal
* reject - bloquer le paquet, l'ajouter au journal et envoyer un `TCP reset` si le protocole est TCP ou un `ICMP port unreachable` si le protocole est UDP
* sdrop - bloquer le paquet sans écriture dans le journal

### Protocoles :

Le champ suivant c'est le protocole. Il y a trois protocoles IP qui peuvent être analysez par Snort : TCP, UDP et ICMP.


### IP Addresses:

La section suivant traite les adresses IP et les numéros de port. Le mot `any` peut être utilisé pour définir "n'import quelle adresse". On peut utiliser l'adresse d'une seule machine ou un block avec la notation CIDR. 

Un opérateur de négation peut être appliqué aux adresses IP. Cet opérateur indique à Snort d'identifier toutes les adresses IP sauf celle indiquée. L'opérateur de négation est le `!`.

A negation operator can be applied to IP addresses. This operator tells Snort to match any IP address except the one indicated by the listed IP address. The negation operator is indicated with a "!". Par exemple, la règle du premier exemple peut être modifiée pour alerter pour le trafic dont l'origine est à l'extérieur du réseau :

```
alert tcp !192.168.1.0/24 any -> 192.168.1.0/24 111
(content: "|00 01 86 a5|"; msg: "external mountd access";)
```

### Port Numbers:

Les ports peuvent être spécifiés de différentes manières, y-compris `any`, une définition numérique unique, une plage de ports ou une négation.

Les plages de ports utilisent l'opérateur `:`, qui peut être utilisé de différentes manières :

```
log udp any any -> 192.168.1.0/24 1:1024
```

Journaliser le traffic UDP venant d'un port compris entre 1 et 1024.

```
log tcp any any -> 192.168.1.0/24 :6000
```

Journaliser le traffic TCP venant d'un port plus bas ou égal à 6000.

```
log tcp any :1024 -> 192.168.1.0/24 500:
```

Journaliser le traffic TCP venant d'un privilégié (bien connu) plus grand ou égal à 500 jusqu'au port 1024.

### Direction Operator:

L'opérateur de direction `->`indique l'orientation ou la "direction" du trafique. 

Il y a aussi un opérateur bidirectionnel, indiqué avec le symbole `<>`, utile pour analyser les deux côtés de la conversation. Par exemple une telnet :

```
log 192.168.1.0/24 any <> 192.168.1.0/24 23
```

## Alertes et logs Snort

Si Snort détecte un paquet qui correspond à une règle, il envoie un message d'alerte ou il journalise le message. Les alertes peuvent être envoyées au syslog, journalisées dans un fichier text d'alertes ou affichées directement à l'écran.

To put this into perspective, let’s examine the logging and alerting areas of a system. For this discussion, the system sends alerts to the syslog facility and the offending network packet(s) to an IP-based directory structure. All alerts are logged via syslog to a file called "alerts" in the file /var/adm/snort/alerts. Any alerting message found in this file will have corresponding offending network packets logged in the same directory as the alert file but under the IP address of the source packet.

Using the rule in Figure 1, from above:

alert tcp any any -> 192.168.1.0/24 111
(content:"|00 01 86 a5|"; msg: "mountd access";)

When Snort inspects and matches the above rule to an offending network packet(s), an alerting message is sent to syslog stating that a "mountd access" violation has occurred. This message is recorded in the file /var/adm/snort/alerts and the actual network packet(s) causing the alert is recorded in a file based on the source IP address of the offending packet(s), (i.e. /var/adm/snort/a.b.c.d).

Some problems may occur when filtering log entries into an IP-named file. For one, multiple alerts may involve one IP address. Under this condition, the offending packets violating each unique rule are sent to the same IP-named file; and mapping the specific alert to the offending packet(s) then demands a search and locate approach that could be time consuming.

## Exercises

Réaliser des captures d'écran des exercices suivants et les ajouter à vos réponses.

### Trouver votre nom :

Considérer la règle simple suivante:

alert tcp any any -> any any (msg:"Mon nom!"; content:"Rubinstein";sid:1000001;rev:1;)

**Question 1: Qu'est-ce qu'elle fait la règle et comment ça fonctionne ?**

Utiliser un éditeur et créer un fichier `myrules.rules` sur votre répertoire home. Rajouter une règle comme celle montrée avant avec votre nom. Lancer snort avec la commande suivante :

```
sudo snort -c myrules.rules -i eth0
```

**Question 2: Que voyez-vous quand le logiciel est lancé ? Qu'est-ce que ça vaut dire ? **

Aller à un site web contenant votre nom dans son text (il faudra chercher un peu pour trouver un site en http...). Ensuite, arrêter Snort avec `Control-C`.

**Question 3: Que voyez-vous ? **

Aller au répertoire /var/log/snort. Ouvrir le fichier `alert`. Vérifier qu'il a des alertes pour votre nom.

**Question 4: A quoi ressemble l'alerte ? Qu'est-ce que chaque champ veut dire ?**

### Detecter une visite à Wikipedia

Ecrire une règle qui journalise (sans alerter) un message à chaque fois que Wikipedia est visité **DEPUIS VOTRE** station. **Ne pas utiliser une règle qui détecte un string ou du contenu**.

**Question 5: Quelle est votre règle ? Où le message a-t'il été journalisé ? Qu'est-ce qui a été journalisé ?**


### Detecter un ping d'un autre système

Ecrire une règle qui alerte à chaque fois que votre système reçoit un ping depuis une autre machine. Assurez-vous que ça n'alerte pas quand c'est vous qui envoyez le ping vers un autre système !

**Question 6: Quelle est votre règle ? Comment avez-vous fait pour que ça identifie seulement les pings entrants ? Où le message a-t'il été journalisé ? Qu'est-ce qui a été journalisé ?**


### Detecter une tentative de login SSH

Activer SSH pour votre système.

Vérifier que vous arrivez à vous connecter depuis un voisin.

Essayer d'écrire une règle qui Alerte qu'une tentative de session SSH a été faite. Si vous avez besoin de plus d'information, servez-vous par exemple de Wireshark pour analyser les échange lors de la tentative de connexion. 

**Question 7: Quelle est votre règle ? Montrer la règle et expliquer comment elle fonctionne. Montre le message d'alerte enregistré dans le fichier d'alertes.
**