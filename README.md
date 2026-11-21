# ZTE ZX279128S U-Boot TFTP Recovery & Flashing Reference

**Target Architecture:** ZTE Microelectronics / Sanechips ZX279128S (ARMv7 Dual Cortex-A9)  
**Target Hardware:** ZTE ZXHN F6600P, F670, F680, F673, and related GPON ONT / Gateway series  
**Document Purpose:** Hardware unbricking, protocol documentation, and OpenWrt installation reference  

> [!NOTE]
> **Disclaimer & Intended Use:**  
> This documentation and utility are provided for educational research, device recovery (unbricking), and installing authorized open-source operating systems (e.g., OpenWrt) on devices you legally own. Modifying ISP-leased equipment may violate terms of service. This document does not provide methods for GPON credential spoofing or unauthorized network access.

Author's note: This is the initial findings on attempting to port OpenWrt to a F6600P. This might be useful for some people. I eventually plan to release the port once it is tested on device. 
---

## 1. Overview & Protocol Analysis

When attempting to unbrick or flash custom firmware onto a ZTE router using the **Reset Button Hold (5–6 seconds)** recovery mode, standard RFC-compliant TFTP servers (`dnsmasq`, `tftpd64`, `tftpd-hpa`) fail to transfer firmware.

### Network Capture Behavior (`tcpdump`)
```text
1. Router U-Boot -> Workstation : TFTP RRQ "upgrade.bin" (timeout 5, blksize 1468)
2. Workstation   -> Router U-Boot : TFTP OACK (blksize 1468)
3. Router U-Boot -> Workstation : [ABORT] (No ACK 0, transfer terminated, reboots after 2s)
```

### Root Cause
1. **Recovery Flag Activation:**  
   During early boot, holding the physical Reset button executes `check_key_restore` (`0x4602D800`), setting an internal flag in memory:
   ```arm
   0x46012644:  ldr   r4, =0x46087FBC       ; Base descriptor in BSS
   0x46012658:  mov   r3, #1
   0x4601265C:  strb  r3, [r4, #0x45C]      ; [0x46087FBC + 0x45C] = [0x46088418] = 1
   ```
2. **Proprietary TFTP Option Requirement:**  
   When `[0x46088418] == 1`, U-Boot's `TftpHandler` (`0x4602B380`) expects the TFTP server's **Option Acknowledgment (OACK)** packet to include two non-standard options:
   * `user`
   * `pass`
3. **Failure Condition:**  
   If `user` and `pass` are omitted (as standard RFC TFTP servers do), U-Boot emits `"Get UserName or PassWord from Tftp failed!"`, sets `NetState = 3` (`NETLOOP_FAIL`), immediately terminates the session, and reboots.

---

## 2. Cryptographic Analysis of the Authentication Tokens

Reverse engineering of the U-Boot binary reveals that the authentication mechanism relies entirely on public standard test vectors and default factory strings.

### 2.1 Credentials (`root` / `root`)
U-Boot reads environment variables `env_na` and `env_pa`:
```text
env_na==@@;
env_pa==@@;
```
It passes these strings through an internal transformation (`0x4600EDA4`):
$$\text{out}[i] = \sim(\text{in}[i] + 0\text{x}50) \ \& \ 0\text{xFF}$$

* `= (0x3D)` $\to$ `~0x8D & 0xFF` = `0x72` (`'r'`)
* `@ (0x40)` $\to$ `~0x90 & 0xFF` = `0x6F` (`'o'`)
* `@ (0x40)` $\to$ `~0x90 & 0xFF` = `0x6F` (`'o'`)
* `; (0x3B)` $\to$ `~0x8B & 0xFF` = `0x74` (`'t'`)

The expected credentials decode directly to **`username = "root"`** and **`password = "root"`**.

### 2.2 Public NIST FIPS-197 AES Key
In `0x4602B454`, U-Boot initializes an **AES-128-ECB** decryption context using a hardcoded 16-byte key at offset `0x4603FC20`:
```text
Offset 0x4603FC20: 2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C
```
This is the literal **NIST FIPS-197 official specification example key** published in standard cryptographic literature (`Key = 2b7e151628aed2a6abf7158809cf4f3c`).

### 2.3 Required OACK Payload
U-Boot takes the string values provided in the `user` and `pass` OACK fields, decrypts 16 bytes via AES-128-ECB, and compares them against null-padded `"root"`:
```arm
0x4602b4b8:  bl   memcmp(decrypted_user, "root\0\0\0\0\0\0\0\0\0\0\0\0", 16)
0x4602b4e8:  bl   memcmp(decrypted_pass, "root\0\0\0\0\0\0\0\0\0\0\0\0", 16)
```

Encrypting `b"root\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"` with the NIST key yields the token:
```text
Hex:    74 2a 80 a9 22 ce 4b 66 6d 3a ba 66 11 6c 15 b9
Python: b"\x74\x2a\x80\xa9\x22\xce\x4b\x66\x6d\x3a\xba\x66\x11\x6c\x15\xb9"
```
Because this 16-byte ciphertext contains **no null bytes (`\x00`)**, it can safely traverse standard null-terminated C string functions (`strlen`, `strcpy`) inside U-Boot.

---

## 3. Serial UART Console Behavior (Stage-2 U-Boot)

Attempting to interrupt boot via serial UART does not work on production firmware because ZTE stubs out the serial console driver in Stage-2 U-Boot:

`default_serial_console()` resolves to `zte_serial` (`0x4603FAEC`):
* **`tstc()` (`0x4601C66C`):** Returns `0` immediately (`mov r0, #0; bx lr`). It never inspects the UART RX FIFO.
* **`getc()` (`0x4601C664`):** Returns `0xFF` (`mov r0, #0xff; bx lr`).
* **`putc()` (`0x4601C660`):** No-op (`bx lr`). Discards outgoing console characters.

While Stage-1 SPL prints over UART (by writing directly to MMIO registers at `0x94404000`), Stage-2 U-Boot disables interactive serial I/O. Therefore, the network TFTP recovery mechanism is the primary non-destructive unbricking and flashing interface.

---

## 4. Standalone Python TFTP Recovery Daemon

The following standalone script implements an RFC-compliant TFTP server that injects the required ZTE OACK authentication options. It requires no external dependencies outside standard Python 3.

```python
#!/usr/bin/env python3
"""
ZTE ZX279128S TFTP Recovery Daemon
Facilitates unbricking and firmware flashing for ZTE routers running U-Boot.
"""

import argparse
import os
import socket
import struct
import sys
import time

# ZTE Ciphertext for plaintext 'root\0...' using NIST FIPS-197 key (2b7e151628aed2a6abf7158809cf4f3c)
ZTE_AUTH_TOKEN = bytes.fromhex("742a80a922ce4b666d3aba66116c15b9")


def run_server(filename: str, host: str = "0.0.0.0", port: int = 69):
    if not os.path.exists(filename):
        print(f"[-] Error: Target firmware '{filename}' not found.")
        print(f"[-] Ensure the recovery firmware is present at the specified path.")
        sys.exit(1)

    with open(filename, "rb") as f:
        file_data = f.read()

    file_size = len(file_data)
    print(f"[+] Loaded firmware: '{filename}' ({file_size:,} bytes / {file_size / (1024*1024):.2f} MiB)")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((host, port))
    except PermissionError:
        print(f"[-] Error: Binding to port {port} requires root/administrator privileges.")
        sys.exit(1)

    print(f"[+] Listening on UDP {host}:{port}...")
    print("[*] Ready. Power on router while holding the Reset button for ~6 seconds...")

    while True:
        data, client_addr = sock.recvfrom(2048)
        if len(data) < 2:
            continue

        opcode = struct.unpack("!H", data[:2])[0]
        if opcode != 1:  # Opcode 1 = RRQ (Read Request)
            continue

        # Parse requested filename and options
        parts = data[2:].split(b"\x00")
        req_filename = parts[0].decode("latin1", errors="ignore")
        print(f"\n[+] Received RRQ from {client_addr[0]}:{client_addr[1]} for '{req_filename}'")

        blksize = 1468
        timeout = 5
        i = 2
        while i < len(parts) - 1:
            opt_name = parts[i].lower().decode("latin1", errors="ignore")
            opt_val = parts[i + 1].decode("latin1", errors="ignore")
            if opt_name == "blksize":
                blksize = int(opt_val)
            elif opt_name == "timeout":
                timeout = int(opt_val)
            i += 2

        print(f"[*] Negotiated options: blksize={blksize}, timeout={timeout}s")

        # Construct ZTE-compatible OACK packet (Opcode 6)
        oack = struct.pack("!H", 6)
        oack += b"blksize\x00" + str(blksize).encode("ascii") + b"\x00"
        oack += b"timeout\x00" + str(timeout).encode("ascii") + b"\x00"
        oack += b"user\x00" + ZTE_AUTH_TOKEN + b"\x00"
        oack += b"pass\x00" + ZTE_AUTH_TOKEN + b"\x00"

        session_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        session_sock.settimeout(timeout + 2)
        session_sock.sendto(oack, client_addr)
        print("[+] Sent authenticated OACK. Awaiting ACK 0 from U-Boot...")

        try:
            ack_data, _ = session_sock.recvfrom(512)
            ack_op, ack_block = struct.unpack("!HH", ack_data[:4])
            if ack_op != 4 or ack_block != 0:
                print(f"[-] Unexpected response from client: op={ack_op}, block={ack_block}")
                session_sock.close()
                continue
            print("[+] U-Boot acknowledged authentication (ACK 0). Starting transfer...")
        except socket.timeout:
            print("[-] Timeout waiting for ACK 0 from router.")
            session_sock.close()
            continue

        # Stream firmware in blksize chunks
        block_num = 1
        offset = 0
        total_blocks = (file_size + blksize - 1) // blksize
        start_time = time.time()

        while offset < file_size:
            chunk = file_data[offset:offset + blksize]
            data_pkt = struct.pack("!HH", 3, block_num & 0xFFFF) + chunk

            for retry in range(5):
                session_sock.sendto(data_pkt, client_addr)
                try:
                    ack_data, _ = session_sock.recvfrom(512)
                    ack_op, ack_block = struct.unpack("!HH", ack_data[:4])
                    if ack_op == 4 and ack_block == (block_num & 0xFFFF):
                        break
                except socket.timeout:
                    print(f"[-] Retry block {block_num} ({retry + 1}/5)...")
            else:
                print(f"[-] Failed to deliver block {block_num} after 5 retries. Aborting session.")
                break

            offset += blksize
            if block_num % 500 == 0 or offset >= file_size:
                pct = (offset / file_size) * 100
                elapsed = max(time.time() - start_time, 0.01)
                speed_kb = (offset / 1024) / elapsed
                print(f"[*] Progress: {offset:,} / {file_size:,} bytes ({pct:.1f}%) - {speed_kb:.1f} KB/s")

            block_num += 1

        print("[+] Firmware transfer complete! Router is writing to flash and will reboot...")
        session_sock.close()


def main():
    parser = argparse.ArgumentParser(description="ZTE ZX279128S U-Boot TFTP Recovery Daemon")
    parser.add_argument("firmware", nargs="?", default="upgrade.bin", help="Path to firmware binary (default: upgrade.bin)")
    parser.add_argument("--host", default="0.0.0.0", help="Host IP to bind (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=69, help="UDP port (default: 69)")
    args = parser.parse_args()

    run_server(args.firmware, args.host, args.port)


if __name__ == "__main__":
    main()
```

---

## 5. Step-by-Step Flashing Procedure

### 1. Workstation Network Configuration
* Configure your PC's Ethernet interface with a static IPv4 configuration:
  * **IP Address:** `192.168.1.100`
  * **Subnet Mask:** `255.255.255.0`
  * **Default Gateway:** `192.168.1.1`

### 2. Firmware Preparation
* Copy the target firmware image into the working directory and name it **`upgrade.bin`** (or specify the path as a command-line argument).
* Ensure the firmware image includes the valid ZTE partition header structure (`0x99999999`, `'DDDD'`, `'UUUU'`, `0xAAAAAAAA`) and corresponding CRC32 checksums if flashing on stock U-Boot.

### 3. Start the Server
* Run the recovery daemon (elevated privileges may be required to bind UDP port 69):
  ```sh
  # Linux / macOS
  sudo python3 zte_tftp_server.py upgrade.bin

  # Windows (Run PowerShell / CMD as Administrator)
  python zte_tftp_server.py upgrade.bin
  ```

### 4. Initiate Router Bootloader Recovery
1. Connect an Ethernet cable between your workstation and **LAN Port 1** on the router.
2. Disconnect the power adapter from the router.
3. Using a pin or paperclip, press and hold the **Reset** button.
4. While continuing to hold the Reset button, plug in the power supply.
5. Keep holding the Reset button for **6 seconds** (U-Boot's trigger window is 5.25 seconds).
6. Release the button once the WPS or Internet LED changes state (indicating recovery entry).

### 5. Verification
* The daemon will log the incoming RRQ, reply with the authenticated OACK, receive `ACK 0`, and stream the blocks to the router.
* Once the progress reaches 100%, allow 1–2 minutes for the bootloader to write the payload to flash and initiate an automatic reboot.
