# software-security-labs

Write-ups from a software-security lab course I did at ÉTS (Montréal), winter 2026. The focus is low-level exploitation: how memory-corruption bugs work, how to turn them into control of a program, and what a developer should do to prevent them. Each write-up walks through the reasoning, not just the final payload.

Everything was done on legal targets only: deliberately vulnerable challenge binaries in a controlled lab, on local Linux and Windows virtual machines. No real systems were touched.

Français : [README.fr.md](README.fr.md).

## Labs

| Lab | Topic | Write-up |
|-----|-------|----------|
| 1 | Buffer overflow exploitation on Linux and Windows: local-variable overwrite, ret2win, ret2shellcode with ASLR bypass, and a heap overflow | [EN](lab1-buffer-overflow/README.md) · [FR](lab1-buffer-overflow/README.fr.md) |

More will be added as I finish them.

## Layout

```
software-security-labs/
  README.md                 this index (English)
  README.fr.md              this index (French)
  lab1-buffer-overflow/
    README.md               English write-up
    README.fr.md            French write-up
    img/                     screenshots of the exploitation steps
```

## Scope and ethics

These write-ups document exploitation against targets I was allowed to test: intentionally vulnerable binaries handed out in a controlled university lab, run on local VMs. No repository here ships a real-world exploit, and the challenge flags shown are specific to that lab instance and worthless anywhere else. The point is to understand memory corruption well enough to write safer code and recognize the bug class in review.
