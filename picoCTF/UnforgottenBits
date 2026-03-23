# picoCTF Forensics Writeup – UnforgottenBits

## Challenge Description

Download the disk image and find the flag.

**Hint:** *"There are no hints here, but there are plenty on the disk."*

---

## Step 1: Extract the Disk Image

```bash
binwalk -e disk.flag.img
```

This creates many folders and files. Focus on:

* `ext-root`
* `ext-root-0`
* `iso-root`

---

## Step 2: Explore the Filesystem

```bash
cd _disk.flag.img.extracted
cd ext-root-0
ls
```

```text
bin  etc  home  lib  root  sbin  usr  var
```

```bash
cd home/yone
ls
```

```text
gallery  irclogs  Maildir  notes
```

---

## Step 3: Collect Information

### Notes

```text
chizazerite
guldulheen
I keep forgetting this, but it starts like: yasuoaatrox...
```

*(Misleading password hints)*

### IRC Logs

```text
Use steghide
password: akalibardzyratrundle

Use openssl AES-CBC
salt=0f3fa17e...
key=58593a75...
iv=7a12fd4d...

"I seed my crypto keys with uuids"
```

**Gives:**
* steghide password
* encryption info
* UUID hint

---

## Step 4: Extract Hidden Data

```text
1.bmp  2.bmp  3.bmp  7.bmp
```

```bash
for f in *.bmp; do
  steghide extract -sf "$f" -p akalibardzyratrundle
done
```

For `7.bmp`:

```bash
steghide extract -sf 7.bmp -p yasuoaatroxashecassiopeia
```

---

## Step 5: Decryption Attempt (Decoy)

```bash
openssl enc -aes-256-cbc -d \
-K <given key> \
-iv <given iv> \
-in file.enc -out file.dec
```

Output = readable books → not the flag

---

## Step 6: Re-evaluate

Shift focus to disk forensic artifacts.

---

## Step 7: Find Hidden Data

```bash
find . -type f -exec strings -a {} + 2>/dev/null | grep -E "[01]{10,}\.[01]{3,}"
```

Example:

```text
10101010101.010
11100101010.111
```

---

## Step 8: Identify Encoding

* Only 0/1
* Has decimal point
* Fixed length

→ **Base-φ (Golden Ratio)**

---

## Step 9: Decode

$$ \phi = \frac{1 + \sqrt{5}}{2} $$

**Each chunk:**
* 11 bits left
* 3 bits right
* length = 15

```python
from math import sqrt

phi = (1 + sqrt(5)) / 2

def decode_phi_chunk(chunk):
    if '.' not in chunk:
        return ''

    left, right = chunk.split('.')
    total = 0

    for i, bit in enumerate(left):
        if bit == '1':
            total += phi ** (len(left) - 1 - i)

    for i, bit in enumerate(right):
        if bit == '1':
            total += phi ** (-(i + 1))

    return chr(round(total))

def decode(data):
    result = ""
    for i in range(0, len(data), 15):
        chunk = data[i:i+15]
        if len(chunk) == 15:
            result += decode_phi_chunk(chunk)
    return result

with open("flag.txt") as f:
    encoded = f.read().strip()

print(decode(encoded))
```

---

## Step 10: Extract Key and IV

```text
salt=2350e88cbeaf16c9
key=a9f86b874bd927057a05408d274ee3a88a83ad972217b81fdc2bb8e8ca8736da
iv=908458e48fc8db1c5a46f18f0feb119f
```

---

## Step 11: Final Decryption

```bash
openssl enc -aes-256-cbc -d \
-K a9f86b874bd927057a05408d274ee3a88a83ad972217b81fdc2bb8e8ca8736da \
-iv 908458e48fc8db1c5a46f18f0feb119f \
-in ledger.1.txt.enc -out ledger.1.txt.dec
```

---

## Step 12: Flag

```bash
cat ledger.1.txt.dec
```

**Flag:** `picoCTF{f473_53413d_de7d35ee}`
```

