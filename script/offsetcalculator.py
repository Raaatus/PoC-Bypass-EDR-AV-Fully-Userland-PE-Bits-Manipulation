# ImageBase constant
image_base = 0x14000000

try:
    while True:
        # Get user input for RVAs
        source_rva = int(input("Enter source RVA (in hex): 0x"), 16)
        dest_rva = int(input("Enter destination RVA (in hex): 0x"), 16)
        
        # Convert RVA to VA
        source_va = source_rva + image_base
        dest_va = dest_rva + image_base
        
        # Calculate offset for JMP instruction
        jmp_size = 5  # Size of JMP rel32 instruction
        offset = dest_va - (source_va + jmp_size)
        
        # Display offset in little-endian format
        offset_bytes = offset.to_bytes(4, byteorder='little', signed=True)
        offset_hex = ' '.join(f'{b:02X}' for b in offset_bytes)
        
        print(f"Offset: {offset} ({hex(offset)})")
        print(f"Offset bytes (little-endian): {offset_hex}")
        print("--------------------------------------")
        
except KeyboardInterrupt:
    print("\nProgram terminated by user (Ctrl+C)")