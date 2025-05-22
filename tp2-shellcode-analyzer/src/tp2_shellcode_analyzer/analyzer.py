import pylibemu
import logging

logging.basicConfig(level=logging.INFO)

def analyze_shellcode(shellcode: bytes):
    emulator = pylibemu.Emulator()
    offset = emulator.shellcode_getpc_test(shellcode)
    logging.info(f"Offset trouvé: {offset}")
    emulator.prepare(shellcode, offset)
    emulator.test()
    print(emulator.emu_profile_output)

def main():
    with open("shellcode.txt", "rb") as f:
        shellcode = f.read().strip()
    logging.info(f"[+] Testing shellcode of size {len(shellcode)} bytes")
    analyze_shellcode(shellcode)
