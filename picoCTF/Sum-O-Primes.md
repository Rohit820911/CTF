# Sum-O-Primes (RSA)

In RSA, you only get `n` (the product) and `e` (the exponent). Factoring `n` into `p` and `q` is super hard.

But this challenge gave us:

```

x = p + q

```

As soon as you have the **sum** and the **product** of two numbers, the encryption is basically game over. It stops being a *crypto* problem and becomes a *high school algebra* problem.

---

## The Math Hack

We know:

```

p + q = x
p × q = n

```

Any two numbers are roots of the quadratic equation:

```

t² - (sum)t + (product) = 0

```

So in our case:

```

t² - xt + n = 0

```

Using the quadratic formula:

```

p, q = (x ± √(x² - 4n)) / 2

````

---

## My Script

Since we’re dealing with massive numbers (ASCII → Hex), I used Python:

```python
import math

# Pasting the hex values from the output file
x_hex = "1626a189dcb3..."  # (truncated for the writeup)
n_hex = "720d66204ec3..."
c_hex = "554b90eb12fb..."

# Convert hex strings to integers
x = int(x_hex, 16)
n = int(n_hex, 16)
c = int(c_hex, 16)
e = 65537

# Step 1: Solve the quadratic
D = x**2 - 4*n
sqrt_D = math.isqrt(D)  # Integer square root

p = (x + sqrt_D) // 2
q = (x - sqrt_D) // 2

# Step 2: Compute private key
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

# Step 3: Decrypt
m = pow(c, d, n)
flag = bytes.fromhex(hex(m)[2:]).decode()

print(f"Got the flag: {flag}")
````

---

## Why It Worked

The whole point of RSA is that factoring is hard.

But by giving us the **sum (`p + q`)**, they gave us a shortcut.

Instead of brute-force factoring (which could take billions of years), we just solved a simple quadratic equation — something a computer can do in **0.0001 seconds**.

```
