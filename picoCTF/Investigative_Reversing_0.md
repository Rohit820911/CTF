
---

# Investigative Reversing 0

## Description

We have recovered a binary and an image. See what you can make of it. There should be a flag somewhere.

---

## Analysis

First, I used **Ghidra** on the mystery file and then analyzed the `main` function very carefully:

```c
void main(void)

{
  FILE *__stream;
  FILE *__stream_00;
  size_t sVar1;
  long in_FS_OFFSET;
  int local_54;
  int local_50;
  char local_38 [4];
  char local_34;
  char local_33;
  char local_29;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  __stream = fopen("flag.txt","r");
  __stream_00 = fopen("mystery.png","a");
  if (__stream == (FILE *)0x0) {
    puts("No flag found, please make sure this is run on the server");
  }
  if (__stream_00 == (FILE *)0x0) {
    puts("mystery.png is missing, please run this on the server");
  }
  sVar1 = fread(local_38,0x1a,1,__stream);
  if ((int)sVar1 < 1) {
    exit(0);
  }
  puts("at insert");
  fputc((int)local_38[0],__stream_00);
  fputc((int)local_38[1],__stream_00);
  fputc((int)local_38[2],__stream_00);
  fputc((int)local_38[3],__stream_00);
  fputc((int)local_34,__stream_00);
  fputc((int)local_33,__stream_00);
  for (local_54 = 6; local_54 < 0xf; local_54 = local_54 + 1) {
    fputc((int)(char)(local_38[local_54] + '\x05'),__stream_00);
  }
  fputc((int)(char)(local_29 + -3),__stream_00);
  for (local_50 = 0x10; local_50 < 0x1a; local_50 = local_50 + 1) {
    fputc((int)local_38[local_50],__stream_00);
  }
  fclose(__stream_00);
  fclose(__stream);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return;
}
```

---

## Understanding the Logic

If you analyze this code, it tells us how the flag is written into the image.

### First 6 characters → same

```c
fputc((int)local_38[0],__stream_00);
fputc((int)local_38[1],__stream_00);
fputc((int)local_38[2],__stream_00);
fputc((int)local_38[3],__stream_00);
fputc((int)local_34,__stream_00);
fputc((int)local_33,__stream_00);
```

---

### Next characters (index 6 to 14) → +5

```c
for (local_54 = 6; local_54 < 0xf; local_54 = local_54 + 1) {
  fputc((int)(char)(local_38[local_54] + '\x05'),__stream_00);
}
```

So we need to **subtract 5** to get original characters.

---

### Index 15 → -3

```c
fputc((int)(char)(local_29 + -3),__stream_00);
```

So we need to **add 3** to reverse it.

---

### Last part (index 16 to 25) → same

```c
for (local_50 = 0x10; local_50 < 0x1a; local_50 = local_50 + 1) {
  fputc((int)local_38[local_50],__stream_00);
}
```

---

## Checking the Image

Use `xxd` command to see encoding of the image. In Ghidra also we can see the tail part of the image:

```bash
xxd mystery.png | tail
```

Output:

```
0001e7f0: 82 20 08 82 20 08 82 20 08 82 20 64 1f 32 12 21  . .. .. .. d.2.!
0001e800: 08 82 20 08 82 20 08 82 20 08 42 f6 21 23 11 82  .. .. .. .B.!#..
0001e810: 20 08 82 20 08 82 20 08 82 20 64 1f 32 12 21 08   .. .. .. d.2.!.
0001e820: 82 20 08 82 20 08 82 20 08 42 f6 21 23 11 82 20  . .. .. .B.!#.. 
0001e830: 08 82 20 08 82 20 08 82 20 64 1f 32 12 21 08 82  .. .. .. d.2.!..
0001e840: 20 08 82 20 08 82 20 08 42 f6 21 23 11 82 20 08   .. .. .B.!#.. .
0001e850: 82 20 08 82 20 08 82 20 64 17 ff ef ff fd 7f 5e  . .. .. d......^
0001e860: ed 5a 9d 38 d0 1f 56 00 00 00 00 49 45 4e 44 ae  .Z.8..V....IEND.
0001e870: 42 60 82 70 69 63 6f 43 54 4b 80 6b 35 7a 73 69  B`.picoCTK.k5zsi
0001e880: 64 36 71 5f 33 35 34 30 36 37 32 61 7d           d6q_3540672a}

```

---

## Decoding the Middle Part

Now you understand the whole logic. You can write a Python script, use AI, or solve manually.

### Middle part decoding:

```
K = 75 → 75 - 5 = 70 → F  
. = 46 → 46 - 5 = 41 → )  
k = 107 → 107 - 5 = 102 → f  
5 = 53 → 53 - 5 = 48 → 0  
z = 122 → 122 - 5 = 117 → u  
s = 115 → 115 - 5 = 110 → n  
i = 105 → 105 - 5 = 100 → d  
d = 100 → 100 - 5 = 95 → _
```

So:

```
F)f0und_
```

---

### Index 15 fix (+3)

```
q = 113 → 113 + 3 = 116 → t
```

---

### Last part (same)

```
_3540672a}
```

---

## Reconstructed Flag

From extracted data:

```
picoCTF)f0und_1t_3540672a}
```

The `)` appears because `{` (ASCII 123) + 5 = 128, which is not a valid ASCII character.

So we correct it:

---

## Final Flag

```
picoCTF{f0und_1t_3540672a}
```

---


---
