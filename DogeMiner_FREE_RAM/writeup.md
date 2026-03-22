# DogeMiner_FREE_RAM —  write-up (Zero Days)

**Category:** reverse (Windows **PyInstaller**, **Python 3.13**) 
---
 **Challenge binary:** `DogeMiner_FREE_RAM.exe` 



---

## Context

![THM challenge page — DogeMiner](./capture/challenges.png)

## Step 1 — PyInstaller on the PE

```bash
file DogeMiner_FREE_RAM.exe
strings DogeMiner_FREE_RAM.exe | grep -iE 'pyi|PyMarshal|python'
```

PE with embedded **PyInstaller** / **`python313.dll`** (not plain native-only).

![`file` / `strings` — PyInstaller](./capture/file.png)

## Step 2 — Extract

```bash
curl -sL -O https://raw.githubusercontent.com/extremecoders-re/pyinstxtractor/master/pyinstxtractor.py
python3 pyinstxtractor.py DogeMiner_FREE_RAM.exe
```

→ **`DogeMiner_FREE_RAM.exe_extracted/DogeMiner_FREE_RAM.pyc`**

![pyinstxtractor — entry point `DogeMiner_FREE_RAM.pyc`](./capture/xtraction.png)

## Step 3 — `strings` on the `.pyc`

```bash
cd DogeMiner_FREE_RAM.exe_extracted
strings DogeMiner_FREE_RAM.pyc
```

| Snippet | Meaning |
|---------|---------|
| `DOWNLOADING 64GB RAM` | Banner |
| Four obfuscated lines | XOR chunks for **`much_wow`** |
| `base64`, `b64decode` | Decode pipeline |
| `such_secrets`, `secret_1` … `secret_4`, `much_wow` | Key derivation |
| Prompts / `Such flag!` … | `input()` and checks |
| `DogeMiner_FREE_RAM.py` | Original `.py` name |

`strings` does not give XOR constants, concat order, or **`[::-1]`** — use **`marshal` + `dis`** in  **`solve.py`**.

![`strings` on the `.pyc`](./capture/strings.png)

## Step 4 — `much_wow` + `solve.py`

Bytecode: XOR four blocks → concat **`secret_1+secret_2+secret_3+secret_4`** → Base64 → **`[::-1]`**. Below: same logic as repo file **`solve.py`** (optional check against the extracted **`.pyc`**).

```python
#!/usr/bin/env python3

import base64
import marshal
import os
import sys

SUCH_SECRETS = (
    "Mz[1kig[MegyA",
    "EL3`T:xa1Kxfh",
    "7a7J1]QVrgiRe",
    "gYOockGxeIOg`",
)


def much_wow(such_secrets):
    secret_3 = "".join(chr(ord(c) ^ 3) for c in such_secrets[0])
    secret_2 = "".join(chr(ord(c) ^ 2) for c in such_secrets[1])
    secret_4 = "".join(chr(ord(c) ^ 4) for c in such_secrets[2])
    secret_1 = "".join(chr(ord(c) ^ 1) for c in such_secrets[3])
    raw = secret_1 + secret_2 + secret_3 + secret_4
    text = base64.b64decode(raw).decode("utf-8")
    return text[::-1]


def extract_secrets_from_pyc(path):
    with open(path, "rb") as f:
        f.read(16)
        co = marshal.load(f)
    for c in co.co_consts:
        if isinstance(c, tuple) and len(c) == 4 and all(isinstance(x, str) for x in c):
            return c
    raise ValueError("Tuple de secrets introuvable dans les constantes")


def main():
    key = much_wow(SUCH_SECRETS)
    print("Clé / flag:", key)

    here = os.path.dirname(os.path.abspath(__file__))
    pyc = os.path.join(here, "DogeMiner_FREE_RAM.exe_extracted", "DogeMiner_FREE_RAM.pyc")
    if os.path.isfile(pyc):
        t = extract_secrets_from_pyc(pyc)
        assert much_wow(t) == key, "Mismatch avec les constantes du .pyc"
        print("(OK: cohérent avec", pyc + ")")
    else:
        print("(Info: extrait le .pyc avec pyinstxtractor pour vérifier automatiquement.)", file=sys.stderr)


if __name__ == "__main__":
    main()
```

```bash
cd ..   # repo root if you were in exe_extracted/
python3 solve.py
```

![`solve.py` output](./capture/flag.png)
