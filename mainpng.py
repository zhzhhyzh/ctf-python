import os
from PIL import Image
import hashlib
import math
import binascii

# --- Configuration ---
file_path = "payment.png"

# --- File Info & Hashes ---
if not os.path.exists(file_path):
    print(f"File not found: {file_path}")
    exit()

print("=== Basic File Info ===")
print(f"Path: {file_path}")
print(f"Size: {os.path.getsize(file_path)} bytes")

try:
    with open(file_path, "rb") as f:
        data = f.read()
except IOError as e:
    print(f"Error reading file data: {e}")
    exit()

md5 = hashlib.md5(data).hexdigest()
sha256 = hashlib.sha256(data).hexdigest()
print("=== File Hashes ===")
print(f"MD5: {md5}")
print(f"SHA256: {sha256}")

# --- Entropy Analysis ---
def entropy(byte_data):
    """Calculates the entropy (randomness) of byte data."""
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
    print("High entropy detected -> possible hidden/compressed/encrypted data")
else:
    print("Entropy is normal")

# --- LSB Steganography Extraction ---
def extract_lsb(img_path):
    """Attempts to extract printable ASCII from LSBs of an image."""
    try:
        img = Image.open(img_path)
        img = img.convert("RGB")
        pixels = list(img.getdata())
    except Exception as e:
        print(f"ERROR: Could not open image for LSB analysis. File is likely too payment. ({e})")
        return None

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
if lsb_text:
    print(lsb_text[:1000])  # Show first 1000 characters
else:
    print("LSB extraction skipped due to image corruption.")


# --- File Carving for embedded ZIP/JPEG ---
print("=== Embedded File Scan (Signatures) ===")
signatures = {
    "ZIP": b"\x50\x4B\x03\x04",
    "PNG": b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A",
    "JPEG": b"\xFF\xD8\xFF"
}

# The PNG signature check is CRUCIAL here, as your binwalk output didn't find it.
# It should be found at byte 0. If it's not, the corruption is in the header.
for name, sig in signatures.items():
    idx = data.find(sig)
    if idx != -1:
        print(f"{name} signature found at byte {idx}")
    else:
        print(f"No {name} signature detected")

# --- Raw LSB Byte Extraction ---
def extract_lsb_bytes(img_path):
    """Extracts raw LSB bits as a byte array."""
    try:
        img = Image.open(img_path)
        img = img.convert("RGB")
        pixels = list(img.getdata())
    except Exception:
        return bytearray() # Return empty array on failure

    bits = ""
    for r, g, b in pixels:
        bits += bin(r)[-1]
        bits += bin(g)[-1]
        bits += bin(b)[-1]

    byte_array = bytearray()
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) < 8:
            break
        byte_array.append(int(byte, 2))
    return byte_array

# Save the raw LSB data
output_file = "payment_lsb_output.bin"
hidden_bytes = extract_lsb_bytes(file_path)
if hidden_bytes:
    with open(output_file, "wb") as f:
        f.write(hidden_bytes)
    print(f"Raw LSB data extracted to {output_file}")
else:
    print("Raw LSB extraction skipped due to image corruption.")

print("=== Analysis Complete ===")