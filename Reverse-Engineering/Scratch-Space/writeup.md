## Challenge 1: Cryptography

### 1. TL;DR (Executive Summary)
*   **Challenge Name:** Scratch Space
*   **Category:** Reverse Engineering
*   **Difficulty:** [Low - Medium]
*   **The Vulnerability:** [the vulnerability is hardcoded binary making the code vulnerable by making it predictable]
*   **The Break:** [Instead of using gdb to get the flag, I used ghidra and python script to get the flag]

---

### 2. Vulnerability Analysis
The provided x86-64 ELF asks you to guess a passphrase. The passphrase is the flag, and this time it is never stored on disk and never passed to a library function. The program maps a scratch page, builds the real passphrase there, compares it against your guess with a loop of its own, then zeroes the page and unmaps it before printing anything. strings, ltrace and strace all come back empty.

We recommend using pwndbg, a GDB extension commonly used for pwn challenges. Its telescope command can help you inspect the pointer and the memory it points to before the program wipes it.

**My Observations & Logical Trace:**
*   *Observation 1: Description mentioned strings, ltrace and sctrace came empty 
*   *Observation 2: in ghidra, main include hardcodeded local variable: local_24 = 0x311023df
*   *Observation 3: loop for (local_20 = 0; local_20 < 0x2a; local_20 = local_20 + 1) 
                          {       
                            local_24 = local_24 * 0x343fd + 0x269ec3;       
                            *(byte *)((long)__addr + (ulong)local_20) = blob[local_20] ^ (byte)((uint)local_24 >> 0x10);} verifying the precise length of the target passphrase and blob
*   *Observation 4: after seeing blob we can see they array is coming from static memory address 0x404040
---

### 3. The Exploit Strategy (How I Broke It)

1.  **Step 1:** First, I opened the .elf file in ghidra and opened main function
2.  **Step 2:** Next, I checked the loop containing blob it starts with: for (local_20 = 0; local_20 < 0x2a; local_20++) we get 0x2a is equal to 42, and inside the loop 
a = local_24 updates
b = blob is XORed
3.  **Step 3:** Then, I looked further into blob first thing i saw was blob address 0x404040
4.  **Step 4:** After that I simply recorded the bytes from the listing 
5.  **Step 5:** wrote the python code to get the flag
---

### 4. The Final Solver Script (PoC)

```python

blob = bytes.fromhex(
    "54 81 f7 8c 0b 8e 37 d2 "
    "13 52 ac b1 a9 4e c5 ba "
    "20 46 81 3a 17 10 49 bb "
    "f6 7c 7f 91 12 0c 3e 20 "
    "09 b8 c7 ab 8b f3 33 c7 "
    "53 e0"
)

state = 0x311023df #got from local_24
flag = "" #to store flag

for b in blob:
    state = (state * 0x343fd + 0x269ec3) & 0xffffffff #updating the state
    key = (state >> 16) & 0xff #generating the key
    flag += chr(b ^ key) #XORed b with key

print(flag)

```

**Flag Captured:** 

NNS{s34rch3d_7h3_mm4p_b3f0r3_17_w4s_w1p3d}

[**P.S. If you are reading this: this is not the messy, chaotic way I actually scrambled to find the flag during 
live CTF! This writeup represents how I would solve it *now*, after taking the time post-CTF to master Ghidra and
find the cleanest,easiest path forward.]







