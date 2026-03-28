# Investigative Reversing 1

## Description
We have recovered a binary and a few images: image, image2, image3. See what you can make of it. There should be a flag somewhere.

---

## Analysis

I used **Ghidra** to reverse-engineer the provided binary and analyzed the `main` function. The code reads 26 bytes (0x1a) from `flag.txt` and scatters them across three different PNG files (`mystery.png`, `mystery2.png`, `mystery3.png`).

```c

void main(void)

{
  FILE *__stream;
  FILE *__stream_00;
  FILE *__stream_01;
  FILE *__stream_02;
  long in_FS_OFFSET;
  char local_6b;
  int local_68;
  int local_64;
  int local_60;
  char local_38 [4];
  char local_34;
  char local_33;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  __stream = fopen("flag.txt","r");
  __stream_00 = fopen("mystery.png","a");
  __stream_01 = fopen("mystery2.png","a");
  __stream_02 = fopen("mystery3.png","a");
  if (__stream == (FILE *)0x0) {
    puts("No flag found, please make sure this is run on the server");
  }
  if (__stream_00 == (FILE *)0x0) {
    puts("mystery.png is missing, please run this on the server");
  }
  fread(local_38,0x1a,1,__stream);
  fputc((int)local_38[1],__stream_02);
  fputc((int)(char)(local_38[0] + '\x15'),__stream_01);
  fputc((int)local_38[2],__stream_02);
  local_6b = local_38[3];
  fputc((int)local_33,__stream_02);
  fputc((int)local_34,__stream_00);
  for (local_68 = 6; local_68 < 10; local_68 = local_68 + 1) {
    local_6b = local_6b + '\x01';
    fputc((int)local_38[local_68],__stream_00);
  }
  fputc((int)local_6b,__stream_01);
  for (local_64 = 10; local_64 < 0xf; local_64 = local_64 + 1) {
    fputc((int)local_38[local_64],__stream_02);
  }
  for (local_60 = 0xf; local_60 < 0x1a; local_60 = local_60 + 1) {
    fputc((int)local_38[local_60],__stream_00);
  }
  fclose(__stream_00);
  fclose(__stream);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

```

---

## Understanding the Logic

The 26 bytes of the flag are stored in a buffer starting at `local_38`. Due to stack arrangement, `local_34` is index 4 and `local_33` is index 5.

### Scattering Breakdown:
* **Index 0:** Written to `mystery2.png` with a **+0x15** (21) offset.
* **Index 1, 2, 5:** Written directly to `mystery3.png`.
* **Index 3:** Written to `mystery2.png` after being **incremented 4 times** (inside the loop for indices 6-9).
* **Index 4:** Written directly to `mystery.png`.
* **Index 6-9:** Written directly to `mystery.png`.
* **Index 10-14:** Written directly to `mystery3.png`.
* **Index 15-25:** Written directly to `mystery.png`.

---

## Checking the Images

I used `xxd` to check the tail of each PNG file (looking past the `IEND` chunk).

### mystery.png
```bash
xxd mystery.png | tail 
0001e7f0: 8220 0882 2008 8220 0882 2064 1f32 1221  . .. .. .. d.2.!
0001e800: 0882 2008 8220 0882 2008 42f6 2123 1182  .. .. .. .B.!#..
0001e810: 2008 8220 0882 2008 8220 641f 3212 2108   .. .. .. d.2.!.
0001e820: 8220 0882 2008 8220 0842 f621 2311 8220  . .. .. .B.!#.. 
0001e830: 0882 2008 8220 0882 2064 1f32 1221 0882  .. .. .. d.2.!..
0001e840: 2008 8220 0882 2008 42f6 2123 1182 2008   .. .. .B.!#.. .
0001e850: 8220 0882 2008 8220 6417 ffef fffd 7f5e  . .. .. d......^
0001e860: ed5a 9d38 d01f 5600 0000 0049 454e 44ae  .Z.8..V....IEND.
0001e870: 4260 8243 467b 416e 315f 3830 3833 6633  B`.CF{An1_8083f3
0001e880: 6362 7d                                  cb}

```

### mystery2.png
```bash
0001e7e0: 2108 8220 0882 2008 8220 0842 f621 2311  !.. .. .. .B.!#.
0001e7f0: 8220 0882 2008 8220 0882 2064 1f32 1221  . .. .. .. d.2.!
0001e800: 0882 2008 8220 0882 2008 42f6 2123 1182  .. .. .. .B.!#..
0001e810: 2008 8220 0882 2008 8220 641f 3212 2108   .. .. .. d.2.!.
0001e820: 8220 0882 2008 8220 0842 f621 2311 8220  . .. .. .B.!#.. 
0001e830: 0882 2008 8220 0882 2064 1f32 1221 0882  .. .. .. d.2.!..
0001e840: 2008 8220 0882 2008 42f6 2123 1182 2008   .. .. .B.!#.. .
0001e850: 8220 0882 2008 8220 6417 ffef fffd 7f5e  . .. .. d......^
0001e860: ed5a 9d38 d01f 5600 0000 0049 454e 44ae  .Z.8..V....IEND.
0001e870: 4260 8285 73                             B`..s

```

### mystery3.png
```bash
xxd mystery3.png | tail
0001e7e0: 2108 8220 0882 2008 8220 0842 f621 2311  !.. .. .. .B.!#.
0001e7f0: 8220 0882 2008 8220 0882 2064 1f32 1221  . .. .. .. d.2.!
0001e800: 0882 2008 8220 0882 2008 42f6 2123 1182  .. .. .. .B.!#..
0001e810: 2008 8220 0882 2008 8220 641f 3212 2108   .. .. .. d.2.!.
0001e820: 8220 0882 2008 8220 0842 f621 2311 8220  . .. .. .B.!#.. 
0001e830: 0882 2008 8220 0882 2064 1f32 1221 0882  .. .. .. d.2.!..
0001e840: 2008 8220 0882 2008 42f6 2123 1182 2008   .. .. .B.!#.. .
0001e850: 8220 0882 2008 8220 6417 ffef fffd 7f5e  . .. .. d......^
0001e860: ed5a 9d38 d01f 5600 0000 0049 454e 44ae  .Z.8..V....IEND.
0001e870: 4260 8269 6354 3074 6861 5f              B`.icT0tha_```

```


## Decoding the Flag

I mapped the extracted hex values back to their original flag indices based on the reversing logic.

### 1. Reversing Math
* **Index 0:** `0x85` (from mystery2) - `0x15` = `0x70` → **p**
* **Index 3:** `0x73` ('s' from mystery2) - `4` = `0x6f` → **o**

### 2. Direct Extraction
* **mystery3:** * `mystery3[0]` (i) → Index 1
    * `mystery3[1]` (c) → Index 2
    * `mystery3[2]` (T) → Index 5
    * `mystery3[3-7]` (0tha_) → Indices 10–14
* **mystery:**
    * `mystery[0]` (C) → Index 4
    * `mystery[1-4]` (F{An) → Indices 6–9
    * `mystery[5-15]` (1_8083f3cb}) → Indices 15–25

---

## Final Flag

By combining all parts in order (0 to 25):

```text
picoCTF{An0tha_1_8083f3cb}
```

---
