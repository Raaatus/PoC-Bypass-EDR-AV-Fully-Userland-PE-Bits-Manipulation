#!/usr/bin/env python3
"""
PE Section Expander - Adds space to specified PE sections

Usage: 
    - Expand sections: python pe_section_expander.py <input_file> <output_file> --section <section_name> <additional_bytes> [--section <section_name> <additional_bytes> ...]
    - Analyze PE file: python pe_section_expander.py <input_file> --analyze
"""

import sys
import lief
import os
import argparse


def align(value, alignment):
    """Align value to the next multiple of alignment"""
    return ((value + alignment - 1) // alignment) * alignment


def analyze_pe_file(input_file):
    """Analyze PE file and display information about each section and available space"""
    binary = lief.parse(input_file)
    
    if not binary:
        print(f"Error: Unable to parse {input_file}")
        return False
    
    file_alignment = binary.optional_header.file_alignment
    section_alignment = binary.optional_header.section_alignment
    
    print(f"\nPE File Analysis: {input_file}")
    print(f"File Alignment: 0x{file_alignment:X}")
    print(f"Section Alignment: 0x{section_alignment:X}")
    print(f"Size of Image: 0x{binary.optional_header.sizeof_image:X}")
    
    # Better table format
    format_str = "{:<10} {:<12} {:<12} {:<12} {:<20} {:<15}"
    
    print("\nSection Information:")
    print("-" * 80)
    print(format_str.format("Name", "VirtAddr", "VirtSize", "RawSize", "Free Space", "Next Section"))
    print("-" * 80)
    
    for i, section in enumerate(binary.sections):
        # Calculate space within current section alignment
        aligned_vsize = align(section.virtual_size, section_alignment)
        space_in_section = aligned_vsize - section.virtual_size
        
        # Calculate space until next section
        if i < len(binary.sections) - 1:
            next_section = binary.sections[i + 1]
            next_section_name = next_section.name
        else:
            next_section_name = "End of Image"
        
        # Print section details
        print(format_str.format(
            section.name,
            f"0x{section.virtual_address:08X}",
            f"0x{section.virtual_size:08X}",
            f"0x{section.size:08X}",
            f"0x{space_in_section:X} ({space_in_section} bytes)",
            next_section_name
        ))
        
        # Highlight the most important info - safe bytes to add
        print(f"          → Safe to add: {space_in_section} bytes without realigning sections")
        print("-" * 80)
    
    return True

def expand_sections(input_file, output_file, section_expansions):
    """
    Expand multiple sections in a PE file
    
    Args:
        input_file: Path to input PE file
        output_file: Path to save modified PE file
        section_expansions: Dictionary of {section_name: additional_bytes}
    """
    # Parse the PE file
    binary = lief.parse(input_file)
    
    if not binary:
        print(f"Error: Unable to parse {input_file}")
        return False
    
    # Get file and section alignment values
    file_alignment = binary.optional_header.file_alignment
    section_alignment = binary.optional_header.section_alignment
    
    print(f"File Alignment: 0x{file_alignment:X}")
    print(f"Section Alignment: 0x{section_alignment:X}")
    
    # Process each section to expand
    modified_sections = []
    for section_name, additional_bytes in section_expansions.items():
        # Find the section
        target_section = None
        section_index = -1
        
        for idx, section in enumerate(binary.sections):
            if section.name == section_name:
                target_section = section
                section_index = idx
                break
        
        if not target_section:
            print(f"Warning: Section {section_name} not found, skipping")
            continue
        
        print(f"\nModifying {section_name} section:")
        print(f"  Original Virtual Size: 0x{target_section.virtual_size:08X}")
        print(f"  Original Virtual Address: 0x{target_section.virtual_address:08X}")
        print(f"  Original Size of Raw Data: 0x{target_section.size:08X}")
        
        # Calculate new sizes
        original_virtual_size = target_section.virtual_size
        new_virtual_size = original_virtual_size + additional_bytes
        aligned_old_size = align(original_virtual_size, section_alignment)
        aligned_new_size = align(new_virtual_size, section_alignment)
        size_increase = aligned_new_size - aligned_old_size
        
        # Calculate code cave addresses
        code_cave_start = target_section.virtual_address + original_virtual_size
        code_cave_end = target_section.virtual_address + new_virtual_size
        
        # Update section's virtual size
        target_section.virtual_size = new_virtual_size
        
        # IMPORTANT CHANGE: Always modify the section content to include padding bytes,
        # even if we don't need to increase raw size
        current_content = list(target_section.content)
        
        # Calculate how many bytes we need to add to make the file size match the new virtual size
        # If raw size is already larger than virtual size, we might not need to add padding
        required_raw_size = align(target_section.virtual_size, file_alignment)
        
        if required_raw_size > target_section.size:
            # Need to increase raw size
            padding_size = required_raw_size - target_section.size
            target_section.content = current_content + [0] * padding_size
            target_section.size = required_raw_size
            print(f"  Added {padding_size} bytes of padding to raw data")
        else:
            # Just add zeros at the end of the current content up to the virtual size
            # This ensures the code cave is filled with zeros in the file
            if len(current_content) < target_section.virtual_size:
                padding_size = target_section.virtual_size - len(current_content)
                # Make sure we don't exceed the current raw size
                new_content_size = min(len(current_content) + padding_size, target_section.size)
                padding_to_add = new_content_size - len(current_content)
                
                if padding_to_add > 0:
                    target_section.content = current_content + [0] * padding_to_add
                    print(f"  Added {padding_to_add} bytes of zeros to the code cave area")
                else:
                    print(f"  Section raw size already contains enough space for the code cave")
        
        print(f"  New Virtual Size: 0x{target_section.virtual_size:08X}")
        print(f"  New Virtual Address: 0x{target_section.virtual_address:08X}")
        print(f"  New Size of Raw Data: 0x{target_section.size:08X}")
        
        # Display code cave details
        print(f"\n  Code cave details:")
        print(f"    Start RVA: 0x{code_cave_start:08X}")
        print(f"    End RVA: 0x{code_cave_end:08X}")
        print(f"    Size: 0x{additional_bytes:X} bytes")
        
        # Record this section as modified
        modified_sections.append((section_index, section_name, size_increase))
    
    # Adjust sections and SizeOfImage if necessary
    total_size_increase = 0
    for section_index, section_name, size_increase in modified_sections:
        if size_increase > 0:
            print(f"\nNeed to adjust sections after {section_name} by 0x{size_increase:X} bytes")
            
            # Adjust RVAs of subsequent sections
            for i in range(section_index + 1, len(binary.sections)):
                section = binary.sections[i]
                old_rva = section.virtual_address
                new_rva = align(old_rva + size_increase, section_alignment)
                print(f"  Section {section.name}: 0x{old_rva:08X} -> 0x{new_rva:08X}")
                section.virtual_address = new_rva
            
            total_size_increase += size_increase
    
    # Update SizeOfImage if needed
    if total_size_increase > 0:
        binary.optional_header.sizeof_image += total_size_increase
        print(f"\nUpdated SizeOfImage: 0x{binary.optional_header.sizeof_image:08X}")
    
    # Rebuild and save
    builder = lief.PE.Builder(binary)
    builder.build()
    builder.write(output_file)
    
    print(f"\nModified PE file saved to: {output_file}")
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PE Section Expander - Adds space to specified PE sections")
    parser.add_argument("input_file", help="Path to input PE file")
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--analyze", action="store_true", help="Analyze PE file and display section details")
    group.add_argument("--expand", action="store_true", help="Expand sections in the PE file")
    
    parser.add_argument("output_file", nargs="?", help="Path to save modified PE file (required for --expand)")
    parser.add_argument("--section", nargs=2, action="append", metavar=("SECTION_NAME", "ADDITIONAL_BYTES"),
                       help="Section to expand and bytes to add (can be used multiple times)")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input_file):
        print(f"Error: Input file {args.input_file} not found")
        sys.exit(1)
    
    if args.analyze:
        if analyze_pe_file(args.input_file):
            print("Analysis completed successfully!")
        else:
            print("Analysis failed!")
            sys.exit(1)
    
    elif args.expand:
        if not args.output_file:
            print("Error: output_file is required when using --expand")
            sys.exit(1)
            
        if not args.section or len(args.section) == 0:
            print("Error: At least one --section argument is required")
            sys.exit(1)
            
        # Process sections to expand
        section_expansions = {}
        for section_name, additional_bytes_str in args.section:
            try:
                additional_bytes = int(additional_bytes_str, 0)  # Support for hex with 0x prefix
                section_expansions[section_name] = additional_bytes
            except ValueError:
                print(f"Error: additional_bytes must be a number: {additional_bytes_str}")
                sys.exit(1)
        
        if expand_sections(args.input_file, args.output_file, section_expansions):
            print("Operation completed successfully!")
        else:
            print("Operation failed!")
            sys.exit(1)