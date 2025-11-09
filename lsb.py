import os
from PIL import Image

# --- CONFIGURATION ---
INPUT_IMAGE = "weeeeeee.jpg"
OUTPUT_FILE = "lsb_flag_data.bin"

def extract_lsb_bytes(img_path):
    """Extracts raw bytes hidden in the Least Significant Bit of each color channel."""
    try:
        img = Image.open(img_path).convert("RGB")
    except FileNotFoundError:
        print(f"Error: Image file not found at {img_path}")
        return bytearray()

    pixels = list(img.getdata())
    bits = ""

    # 1. Extract the LSB from the R, G, and B channels of every pixel
    for r, g, b in pixels:
        bits += bin(r)[-1]  # LSB of Red
        bits += bin(g)[-1]  # LSB of Green
        bits += bin(b)[-1]  # LSB of Blue

    # 2. Group the bits into bytes
    byte_array = bytearray()
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) == 8:
            byte_array.append(int(byte, 2))
    
    return byte_array

def extract_strings(data, min_length=4):
    """Scans binary data for printable ASCII strings."""
    readable_strings = []
    current_string = ""
    for byte in data:
        # Check if the character is printable ASCII (32 is space, 126 is tilde)
        if 32 <= byte <= 126:
            current_string += chr(byte)
        else:
            # End of a string, save if long enough
            if len(current_string) >= min_length:
                readable_strings.append(current_string)
            current_string = ""
    
    # Check the last collected string
    if len(current_string) >= min_length:
        readable_strings.append(current_string)
        
    return readable_strings

def check_for_signatures(data):
    """Scans binary data for common file headers (file carving)."""
    signatures = {
        "ZIP": b"\x50\x4B\x03\x04",
        "JPEG": b"\xFF\xD8\xFF\xE0", # Common JPEG signature (includes marker)
        "PNG": b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A"
    }
    
    found_signatures = {}
    for name, sig in signatures.items():
        # Find the signature and store its starting index (offset)
        offset = data.find(sig)
        if offset != -1:
            found_signatures[name] = offset
            
    return found_signatures

# --- MAIN EXECUTION ---
if __name__ == "__main__":
    print(f"--- Starting LSB Extraction for {INPUT_IMAGE} ---")

    hidden_bytes = extract_lsb_bytes(INPUT_IMAGE)

    if not hidden_bytes:
        print("Extraction failed or returned no data.")
    else:
        # Save the raw data to a file for external carving tools if needed
        with open(OUTPUT_FILE, "wb") as f:
            f.write(hidden_bytes)
        
        print(f"\n✅ Raw LSB data extracted and saved to **{OUTPUT_FILE}** ({len(hidden_bytes)} bytes)")

        # 1. CARVING CHECK
        print("\n--- 1. Searching for Embedded File Signatures (Carving Check) ---")
        signatures = check_for_signatures(hidden_bytes)
        
        if signatures:
            print("🚨 HIGH PRIORITY CLUE FOUND! Embedded file detected in LSB data:")
            for name, offset in signatures.items():
                print(f"   -> {name} signature found at byte offset {offset:,}. The flag may be hidden in this file.")
            print(f"\nACTION: Use a tool like `binwalk` or `foremost` on **{OUTPUT_FILE}** to extract the file.")
        else:
            print("   No known file signatures (ZIP, JPEG, PNG) found in the LSB data.")

        # 2. STRING EXTRACTION
        print("\n--- 2. Extracting Printable Text Strings (Plaintext Flag Check) ---")
        strings = extract_strings(hidden_bytes)
        
        found_flag = False
        for s in strings:
            # Print only potentially meaningful long strings (e.g., words > 10 chars)
            if len(s) > 10 or any(word in s.upper() for word in ["BAG", "SHIRE", "ALEXANDER"]):
                print(f"   -> {s}")
                # The "n.BAG" clue you saw previously will appear here.
                if "n.BAG" in s:
                     print("\n*** The previous cryptic clue was confirmed in this list. ***")
                found_flag = True

        if not found_flag:
            print("   No long or meaningful plaintext strings found in the LSB data.")

    print("\n--- Analysis Complete ---")
    print("If you found a unique name/word in the output, use it in the flag format: TARUMT{NAME_NEW ZEALAND}")