# elf-dsmblr

This program disassembles a section of an ELF binary file and prints the resulting assembly code to the console.
Prerequisites

The program requires the following Python packages to be installed:

- lief
- capstone

## Usage

The program is executed from the command line as follows:

`python elf_analysis.py [-h] [-s section_name] [-x] filename`

### Arguments

- `-h` : Help option. Displays program usage information.
- `-s` : Optional. Specifies the section name to disassemble. If not specified, the program will prompt the user to select a section from a list of available sections.
- `-x` : Optional. If specified, the program will display the hexadecimal representation of each instruction.
- `filename` : The name of the ELF binary file to be analyzed.

### Output

The program outputs the assembly code of the selected section to the console. The output includes the virtual address of each instruction, the instruction mnemonic and operands, and (optionally) the hexadecimal representation of each instruction.

###Program Flow

The program performs the following steps:

- Checks that the specified file is an ELF binary.
- Determines the architecture and mode of the binary (32-bit or 64-bit).
- Parses the binary file using LIEF.
- If no section name was specified, prompts the user to select a section from a list of available sections.
- Disassembles the selected section using Capstone.
- Prints the resulting assembly code to the console.
