def ip_to_hex(ip):
    # Split IP into octets and convert to integers
    octets = [int(x) for x in ip.split('.')]
    
    # Convert to hex (keeping the original order)
    hex_value_original = '0x' + ''.join([format(x, '02X') for x in octets])
    
    # Reverse octets for little endian order
    octets.reverse()
    
    # Convert reversed octets to hex
    hex_value_little_endian = '0x' + ''.join([format(x, '02X') for x in octets])
    
    return hex_value_original, hex_value_little_endian

# Example usage
ip = input("Enter IP address (e.g. 192.168.1.1): ")
original, little_endian = ip_to_hex(ip)
print(f"Hex value (original order): {original}")
print(f"Hex value (little endian): {little_endian}")