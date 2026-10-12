# software-security-labs

Write-ups d'un cours de labo en sécurité logicielle fait à l'ÉTS (Montréal), hiver 2026. L'accent est mis sur l'exploitation bas niveau : comment les bugs de corruption mémoire fonctionnent, comment les transformer en contrôle d'un programme, et ce qu'un développeur doit faire pour les empêcher. Chaque write-up déroule le raisonnement, pas seulement la charge utile finale.

Tout a été fait sur des cibles légales uniquement : des binaires de défi volontairement vulnérables dans un labo contrôlé, sur des machines virtuelles Linux et Windows locales. Aucun système réel n'a été touché.

English: [README.md](README.md).

## Labos

| Labo | Sujet | Write-up |
|------|-------|----------|
| 1 | Exploitation de buffer overflow sur Linux et Windows : écrasement de variable locale, ret2win, ret2shellcode avec contournement d'ASLR, et un heap overflow | [EN](lab1-buffer-overflow/README.md) · [FR](lab1-buffer-overflow/README.fr.md) |
| 2 | Exploitation d'applications web : LFI vers RCE, contournements d'upload, brute force CAPTCHA, injection SQL, vol de cookie XSS, injection de commande, et brute force SSH | [EN](lab2-web-exploitation/README.md) · [FR](lab2-web-exploitation/README.fr.md) |

D'autres s'ajouteront au fur et à mesure.

## Organisation

```
software-security-labs/
  README.md                 cet index (anglais)
  README.fr.md              cet index (français)
  lab1-buffer-overflow/
    README.md               write-up anglais
    README.fr.md            write-up français
    img/                     captures des étapes d'exploitation
  lab2-web-exploitation/
    README.md
    README.fr.md
    img/
```

## Périmètre et éthique

Ces write-ups documentent de l'exploitation contre des cibles que j'avais le droit de tester : des binaires volontairement vulnérables distribués dans un labo universitaire contrôlé, exécutés sur des VM locales. Aucun dépôt ici ne livre d'exploit du monde réel, et les flags de défi montrés sont propres à cette instance de labo et sans valeur ailleurs. Le but est de comprendre la corruption mémoire assez bien pour écrire du code plus sûr et reconnaître cette classe de bug en revue.
