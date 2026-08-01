# Overheard at Breakfast - TryHackMe Writeup

I am solving the **Overheard at Breakfast** THM room.

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/69dd4887-99d3-40e9-8e18-5e801d1ff86b" />

After downloading and extracting the provided ZIP file, I got a PNG image.

<img width="1175" height="781" alt="image" src="https://github.com/user-attachments/assets/5971cd52-a600-45df-b992-beb484fdfa86" />

Inside the image, I found the email address:

```text
lambobytelotushotel@gmail.com
```

I used the **user-scanner** tool to gather information about the email.

Repository:
https://github.com/kaifcodec/user-scanner

Install and run:

```bash
source .venv/bin/activate
pip install user-scanner

user-scanner -e lambobytelotushotel@gmail.com
```

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/a117dd40-90cb-4d05-92a0-e5695fb87af0" />

The output showed that the email has a **Gravatar** profile.

<img width="1920" height="1080" alt="screenshot_20260801_214758" src="https://github.com/user-attachments/assets/bb36b674-fdd5-4b37-a88f-bdc8f70d8bb8" />

```text
Gravatar (lambobytelotushotel@gmail.com): Registered
├── avatar_url: https://www.gravatar.com/avatar/d43faafe9d7f056793bd037b8d6e321acad985c222d83775b10d6539e301e931
├── username: cheerfullysongf28e3c3716
├── display_name: Lambo
├── profile_url: https://gravatar.com/cheerfullysongf28e3c3716
├── thumbnail_url: https://1.gravatar.com/avatar/d43faafe9d7f056793bd037b8d6e321acad985c222d83775b10d6539e301e931
├── bio: Funny thing about email hashes, they follow you places you didn't expect. Glad you found the right corner of the internet!
│         Here is your prize: VEhNe1MzY3JlVF9QcjBmaWwzX0g0c19iMzNuX0lkZW50MWZpM2R9
├── location: Byte Lotus Hotel
└── photos: https://1.gravatar.com/avatar/d4a5fc5d3128890778667e24617d7cc0
```

In the bio, I found a Base64-encoded string:

```text
VEhNe1MzY3JlVF9QcjBmaWwzX0g0c19iMzNuX0lkZW50MWZpM2R9
```

I decoded it using:

```bash
echo "VEhNe1MzY3JlVF9QcjBmaWwzX0g0c19iMzNuX0lkZW50MWZpM2R9" | base64 -d
```

Output:

```text
THM{S3creT_Pr0fil3_H4s_b33n_Ident1fi3d}
```

## Flag

```text
THM{S3creT_Pr0fil3_H4s_b33n_Ident1fi3d}
```
