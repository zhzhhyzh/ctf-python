import os
from PIL import Image
import hashlib
import math
import binascii

# --- File Info & Hashes ---
file_path = "weeeeeee.jpg"
if not os.path.exists(file_path):
    print(f"File not found: {file_path}")
    exit()

print("=== Basic File Info ===")
print(f"Path: {file_path}")
print(f"Size: {os.path.getsize(file_path)} bytes")

with open(file_path, "rb") as f:
    data = f.read()

md5 = hashlib.md5(data).hexdigest()
sha256 = hashlib.sha256(data).hexdigest()
print("=== File Hashes ===")
print(f"MD5: {md5}")
print(f"SHA256: {sha256}")

# --- Entropy Analysis ---
def entropy(byte_data):
    if not byte_data:
        return 0
    freq = [0] * 256
    for b in byte_data:
        freq[b] += 1
    ent = 0
    for f in freq:
        if f > 0:
            p = f / len(byte_data)
            ent -= p * math.log2(p)
    return ent

print("=== Entropy Check ===")
file_entropy = entropy(data)
print(f"Entropy: {file_entropy:.4f} bits per byte")
if file_entropy > 7.5:
    print("High entropy detected → possible hidden/compressed/encrypted data")
else:
    print("Entropy is normal")

# --- LSB Steganography Extraction ---
def extract_lsb(img_path):
    img = Image.open(img_path)
    img = img.convert("RGB")
    pixels = list(img.getdata())
    bits = ""
    for r, g, b in pixels:
        bits += bin(r)[-1]  # LSB of Red
        bits += bin(g)[-1]  # LSB of Green
        bits += bin(b)[-1]  # LSB of Blue
    # Convert bits to ASCII
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) < 8:
            continue
        char = chr(int(byte, 2))
        if 32 <= ord(char) <= 126 or char in "\n\r\t":
            chars.append(char)
        else:
            chars.append(".")  # non-printable
    return "".join(chars)

print("=== LSB Steganography ===")
lsb_text = extract_lsb(file_path)
print(lsb_text[:1000])  # Show first 1000 characters

# --- File Carving for embedded ZIP/JPEG ---
print("=== Embedded File Scan ===")
signatures = {
    "ZIP": b"\x50\x4B\x03\x04",
    "PNG": b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A",
    "JPEG": b"\xFF\xD8\xFF"
}

for name, sig in signatures.items():
    idx = data.find(sig)
    if idx != -1:
        print(f"{name} signature found at byte {idx}")
    else:
        print(f"No {name} signature detected")

print("=== Analysis Complete ===")

# Extract raw LSB bytes (8 bits per byte)
def extract_lsb_bytes(img_path):
    img = Image.open(img_path)
    img = img.convert("RGB")
    pixels = list(img.getdata())
    bits = ""
    for r, g, b in pixels:
        bits += bin(r)[-1]
        bits += bin(g)[-1]
        bits += bin(b)[-1]
    # group bits into bytes
    byte_array = bytearray()
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) < 8:
            break
        byte_array.append(int(byte, 2))
    return byte_array

hidden_bytes = extract_lsb_bytes("weeeeeee.jpg")
with open("lsb_output.bin", "wb") as f:
    f.write(hidden_bytes)

print("Raw LSB data extracted to lsb_output.bin")
