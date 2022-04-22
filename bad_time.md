## bad_time_for_reversing

Nous avons 4 fichiers, un executable qui demande de rentrer un pin à 4 chiffres et nous redonne un message de 21 caracteres, un fichier `file.gpg` crypté par GnuPG et deux fichiers textes, l'un indiquant le timestamp lors de l'éxécution du programme et l'autre indiquant le format du message, à savoir, 21 caractères dont les 4 premiers sont `key:` et le reste la clé pour décrypter le gpg.

![](https://i.imgur.com/yw3m2Of.png)



On remarque une chose, en executant le binaire avec le même argument plusieurs fois, le message reçu n'est pas le même. On se doute alors que l'algorithme possède une part "d'aléatoire" et que ça a surement un rapport avec le moment d'execution étant donné le timestamp qui nous est donné.


Ouvrons tout ça sur Ghidra

![](https://i.imgur.com/iI55s8X.png)

On remarque de suite l'appelle à la fonction time avec l'argument NULL (qui renvoie le timestamp actuel) dans la fonction main.
Cependant, le resultat de cet appel est ensuite stocké dans une variable qui n'est alors utilisé principalement que pour écrire dans un fichier `.fil` dans /tmp, donc ce n'est pas ce qui nous interesse.

Avant d'aller plus loin, on remarque qu'on lit le contenu de ce fichier et on le compare avec le timestamp et si la différence n'est pas assez grande alors, on quitte le programme en printant `Nope`. Cela signifie qu'il y a un certain délai à respecter avant de rééxecuter le binaire. On va, modifier l'instruction jg qui vérifie le résultat du test et jump à la suite normale du programme si le délai a été respecté. On patch l'instruction en remplaçant le `JG` par un `JMP` simple, on sauvegarde le patch avec le script python `SavePatch.py`. Ca nous façilitera la vie pour la suite :)

![](https://i.imgur.com/N9gO8NH.png)

Voyons voir, du côté de la fonction xored qui s'occupe de créer le message à partir du pin à 4 symboles. On remarque encore une fois l'appel `time(NULL)`

La convention d'appel en x86 veut que le résultat de cet appel soit stocké dans le registre `EAX`. On va remplacer l'instruction d'appel à `time` par un `MOV` qui va mettre la valeur du timestamp qui nous est donné dans `EAX`.

![](https://i.imgur.com/WSbeQNc.png)

On patch et on save l'instruction encore une fois.

Il nous reste plus qu'à trouver le code pin. On remarque que le premier symbole du pin modifie le premier caractère du message, le deuxième symbole modifie le deuxième caractère...etc.

On va donc jouer sur ça jusqu'à avoir un message commençant par `key:`

On écrit alors ce petit script python :	
``` 
from subprocess import *
import string

symboles = string.printable

index = 0

found = [False,False,False,False]

current = symboles[0]*4

while (not(found[0] and found[1] and found[2] and found[3])):
    if check_output(["./patched", symboles[index]+current[1::]]).decode("utf-8")[49] == 'k':
        found[0]=True
        current=symboles[index]+current[1::]
    if check_output(["./patched", current[0]+symboles[index]+current[2::]]).decode("utf-8")[50] == 'e':
        found[1]=True
        current=current[0]+symboles[index]+current[2::]

    if check_output(["./patched", current[0]+current[1]+symboles[index]+current[3]]).decode("utf-8")[51] == 'y':
        found[2]=True
        current=current[0]+current[1]+symboles[index]+current[3]

    if check_output(["./patched", current[0]+current[1]+current[2]+symboles[index]]).decode("utf-8")[52] == ':':
        found[3]=True
        current=current[0]+current[1]+current[2]+symboles[index]
    index+=1
print("Le pin a utiliser est : "+current+"\n")


```
Ce qui nous donne le pin `5296`

![](https://i.imgur.com/w0HIySK.png)

On essaye d'executer le binaire résultant. Parfois, on remarque que la valeur dans le fichier temporaire `/tmp/.fil`, lorsqu'il existe, interfére avec le résultat. Il vaut mieux le supprimer avant chaque éxécution.
On obtient la clé suivante avec le pin obtenu précédemment :	
`h3ll01t5m3m4r1000`
On peut finalement decrypter le fichier.

Le fichier obtenu semble être un PNG classique avec un QRcode, cependant le QRcode ne nous donne pas le flag. En effecutant un pngsplit sur l'image, on remarque des chunks fcTL ce qui signifie qu'il s'agit en fait d'un apng (un png animé).

![](https://i.imgur.com/bgykxnu.png)

Extrayons les différentes frames de cet APNG

![](https://i.imgur.com/lJUPHM6.png)

On se retrouve avec 11 QRcodes différents.

Le décodage de celui provenant de la 8ème frame nous donne le flag

![](https://i.imgur.com/a476Idq.png)

### Flag
HACKDAY{w3llpl4y3dbr0}
