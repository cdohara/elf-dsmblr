import lief
import sys
import getopt
from capstone import *

# ANSI color codes for prettier output
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[32m"

def usage():
    print("Usage: elf_analysis.py [-h] [-s section_name] [-x] filename")

def precheck(filename):
    if not lief.is_elf(filename):
        print("Program is NOT ELF")
        return False
    binary = lief.parse(filename)
    if not binary:
        print("Failed to parse binary.")
        return False
    machine_type = binary.header.machine_type
    if machine_type == lief.ELF.ARCH.x86_64:
        return CS_ARCH_X86, CS_MODE_64
    elif machine_type == lief.ELF.ARCH.x86:
        return CS_ARCH_X86, CS_MODE_32
    elif machine_type == lief.ELF.ARCH.ARM:
        return CS_ARCH_ARM, CS_MODE_ARM
    elif machine_type == lief.ELF.ARCH.ARM64:
        return CS_ARCH_ARM64, CS_MODE_ARM
    else:
        print(f"Unsupported architecture: {lief.ELF.ARCH.name(machine_type)}")
        return False

def get_section_name(binary):
    print("These sections are available in the program:")
    for section in binary.sections:
        print(f"Section: {section.name}\tSize: {section.size}")
    section_name = input("Section name to disassemble (.text): ") or ".text"
    return section_name

def linear_disass(section, arch, mode, show_hex):
    md = Cs(arch, mode)
    data = bytearray(section.content)
    print(f"{BOLD}Virtual Address:{RESET} {GREEN}0x{section.virtual_address}{RESET}")
    offset = 0
    while offset < len(data):
        instr = next(md.disasm(data[offset:], offset))
        hexstr = ""
        if show_hex:
            hexstr = " ".join("{:02x}".format(x) for x in data[offset:offset+instr.size])
            hexstr = f"\n{GREEN}{hexstr}{RESET}\n"
        print(f"0x{instr.address:x}:\t{GREEN}{BOLD}{instr.mnemonic}{RESET}\t{instr.op_str}{hexstr}")
        offset += instr.size

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hs:x")
    except getopt.GetoptError as err:
        print(str(err))
        usage()
        sys.exit(2)

    section_name = None
    show_hex = False
    for o, a in opts:
        if o == "-h":
            usage()
            sys.exit()
        elif o == "-s":
            section_name = a
        elif o == "-x":
            show_hex = True

    if len(args) != 1:
        usage()
        sys.exit(2)

    filename = args[0]
    arch_mode = precheck(filename)
    if arch_mode:
        binary = lief.parse(filename)
        if section_name is None:
            section_name = get_section_name(binary)
        section = binary.get_section(section_name)
        linear_disass(section, arch_mode[0], arch_mode[1], show_hex)

if __name__ == '__main__':
    main()
