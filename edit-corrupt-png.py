import os
import binascii

def fix_png_signature(input_filename="corrupted.png", output_filename="repaired_flag.png"):
    """
    Reads the corrupted PNG file and overwrites the first 8 bytes with the
    correct 8-byte PNG signature (magic header).
    """
    # The correct 8-byte PNG signature: 89 50 4E 47 0D 0A 1A 0A
    CORRECT_PNG_SIGNATURE = binascii.unhexlify("89504E470D0A1A0A")

    print(f"--- PNG Header Repair Tool ---")
    print(f"Input file: {input_filename}")
    print(f"Output file: {output_filename}")

    if not os.path.exists(input_filename):
        print(f"\n[ERROR] File not found: {input_filename}")
        print("Please ensure 'corrupted.png' is in the same directory as this script.")
        return

    try:
        # Read the entire corrupted file content
        with open(input_filename, 'rb') as f:
            data = bytearray(f.read())
            
        # 1. Overwrite the first 8 bytes with the correct signature
        print(f"\n[INFO] Original first 8 bytes (Hex): {data[:8].hex()}")
        
        # Replace the first 8 bytes
        data[:8] = CORRECT_PNG_SIGNATURE
        
        print(f"[INFO] Repaired first 8 bytes (Hex): {data[:8].hex()}")

        # 2. Save the corrected data to a new file
        with open(output_filename, 'wb') as f:
            f.write(data)
            
        print(f"\n[SUCCESS] PNG signature repaired!")
        print(f"The file '{output_filename}' has been created.")
        print("Please open this file to view the hidden content and find the flag.")
        
    except Exception as e:
        print(f"\n[CRITICAL ERROR] Failed to process file: {e}")

if __name__ == "__main__":
    # Make sure to place your 'corrupted.png' file in the same directory as this script.
    fix_png_signature()