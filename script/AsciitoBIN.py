import sys

def xor_string(input_str, xor_key, label_name):
    # Convertir la chaîne en bytes si ce n'est pas déjà le cas
    if isinstance(input_str, str):
        input_bytes = input_str.encode('utf-8')
    else:
        input_bytes = input_str
    
    # Appliquer XOR à chaque byte
    xored_bytes = [b ^ xor_key for b in input_bytes]
    
    # Formater le résultat
    hex_values = [f"0x{b:02x}" for b in xored_bytes]
    hex_string = ", ".join(hex_values)
    
    # Créer la sortie au format demandé
    output = f"{label_name:<10} db {hex_string}{' ' * (60 - len(hex_string))}; \"{input_str}\" XOR 0x{xor_key:02x}"
    
    return output

def main():
    if len(sys.argv) < 3:
        print("Usage: python xor_string.py <string> <xor_key_hex> [label_name]")
        print("Example: python xor_string.py ws2_32.dll 41")
        return
    
    input_str = sys.argv[1]
    xor_key = int(sys.argv[2], 16)
    label_name = sys.argv[3] if len(sys.argv) > 3 else input_str.split('.')[0]
    
    result = xor_string(input_str, xor_key, label_name)
    print(result)

if __name__ == "__main__":
    main()
    