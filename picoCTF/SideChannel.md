# SideChannel Writeup

## Understanding the Problem

This challenge is about a **timing-based side-channel attack**.

In this type of attack, we don’t break the encryption directly. Instead, we observe how long the program takes to respond. Even small differences in execution time can leak useful information.

For example, if a program checks a PIN digit by digit and stops when it finds a wrong one:

* A correct digit takes slightly more time
* A wrong digit fails faster

So by measuring time carefully, we can guess the correct PIN step by step.

---

## Hints Given

* **Hint 1:** Learn about timing-based side-channel attacks
* **Hint 2 & 3:** No need to reverse the binary
* Just interact with the program and measure timings
* Don’t attack the main server, use the local binary
* The PIN from the local binary is the same as the server

---

## My Approach

At first, I tried checking execution time only once per digit. But the results were not stable because of noise (random delays).

So I improved it:

* For each digit, I ran the test **20 times**
* Then I took the **median time** to reduce noise
* The digit with the **highest time** is most likely correct

Why highest?
Because correct digits take longer to process.

---

## Total Executions

We did:

$$8 \text{ positions} \times 10 \text{ digits} \times 20 \text{ samples} = \mathbf{1600 \text{ executions}}$$

---

## Script Used

```python
import subprocess
import time
import statistics

# Configuration
BINARY = './pin_checker'
SAMPLES = 20  # Number of times to test each digit to find the median
PIN_LENGTH = 8

print(f"[*] Starting Side-Channel Attack on {BINARY}...")
print(f"[*] Sampling {SAMPLES} times per digit to filter noise.")

current_pin = ""

for i in range(PIN_LENGTH):
    digit_results = {}
    
    for digit in "0123456789":
        test_pin = current_pin + digit + "0" * (PIN_LENGTH - i - 1)
        times = []
        
        for _ in range(SAMPLES):
            start = time.perf_counter_ns() # Using nanoseconds for higher precision
            proc = subprocess.Popen(
                [BINARY], 
                stdin=subprocess.PIPE, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True
            )
            proc.communicate(input=test_pin + '\n')
            end = time.perf_counter_ns()
            times.append(end - start)
            
        # The median is the "middle" value, which ignores the massive lag spikes
        digit_results[digit] = statistics.median(times)
        
    # The digit with the highest median execution time is the winner
    best_digit = max(digit_results, key=digit_results.get)
    current_pin += best_digit
    
    print(f"[+] Found Digit {i+1}: {best_digit} | PIN so far: {current_pin.ljust(8, '*')}")

print("-" * 30)
print(f"[🔥] CRACKED PIN: {current_pin}")
print("-" * 30)
```

---

## Result

* **PIN:** 48390513
* **Flag:** picoCTF{t1m1ng_4tt4ck_914c5ec3}

---


