
# not crypto  

````md
## Description
There's crypto in here, but the challenge is *not* crypto... 🤔  
It is based on **reverse engineering**.

---

## Analysis

First, I always start with the `file` command to inspect the binary.

Then I run `checksec`:


````
```bash
checksec --file=not-crypto
````
### Output:

```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   No Symbols      No      0               1               not-crypto
```

### Observations:

* **NX enabled** → No executable stack
* **PIE enabled** → Addresses are randomized
* **No symbols** → Harder to analyze statically

This suggests the flag is **not directly stored in plain form in the binary**.

---

## Strings Analysis

Next, I ran `strings` and found some interesting functions:

* `puts`
* `stdin`
* `fread`
* `memcmp`

The presence of `memcmp` suggests that user input is being compared with something (likely the flag).

---

## Debugging with GDB

I then opened the binary in GDB:

```bash
gdb ./not-crypto
```

Set a breakpoint at `memcmp`:

```bash
break memcmp
run
```

After running the program and entering any input, execution stops at `memcmp`.

---

## Extracting the Flag

At the breakpoint, I inspected the arguments:

```bash
x/s $rdi
```

This reveals the string being compared — which is the flag.

---

## Flag

```
picoCTF{c0mp1l3r_0pt1m1z4t10n_15_pur3_w1z4rdry_but_n0_pr0bl3m?}
```

---


```
```
