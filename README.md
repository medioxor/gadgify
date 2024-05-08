## Gadgify

Gadgify is a fast and simplified gadget enumeration tool for x86_64
binaries with flexible functionality to make filtering for specific gadgets
a breeze. Gadgify can be used to find ROP, JOP, COP, and COOP gadgets by querying
for sequences of instructions using a simplified regex based search. Prebuilt binaries
for Windows and Linux can be found via the following URL:
- https://github.com/medioxor/gadgify/releases

## Features
- Supports x86-64 Portable Executables (PE)
- Supports raw x86-64 files (e.g. a dumped .text section, JIT'd code, etc)
- Intuitive query functionality

## Building
Gadgify can be built cross-platform using cmake which can be acheived using the following commands:
```
cmake -S . build -D CMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

## Usage
```
Usage: Gadgify [--help] [--version] [--gap VAR] --pattern VAR [--raw] binaryPath

Positional arguments:
  binaryPath     Path of the file to search for gadgets. e.g. C:\Windows\System32\ntdll.dll [required]

Optional arguments:
  -h, --help     shows help message and exits
  -v, --version  prints version information and exits
  -g, --gap      The gap between instructions specified in the pattern e.g. searching for the 'mov r*, r1*;call r*;sub *' pattern with a gap of '3' will result in gadgets that can have up to 3 instructions that do not match the pattern between each instruction in the pattern provided. [nargs=0..1] [default: 3]
  -p, --pattern  The pattern to search for. [required]
  -r, --raw      Treat the binary as raw executable code and not as a PE.
```

## Usage examples
- Search for ROP gadgets but ensure up to 5 random instructions preceded the return instruction:
```
gadgify.exe -p "ret;" -g 5 C:\Windows\System32\ntdll.dll
*SNIP*
0x0011b1df: mov eax, 0x80000022; mov rbx, [rsp+0x40]; add rsp, 0x30; pop rdi; ret;
0x0011b236: mov eax, 0x01; ret;
0x0011b23c: int3; sbb eax, eax; ret;
0x0011b2b0: pop r14; ret;
0x0011b353: pop r15; pop r14; pop r12; ret;
0x0011b3a0: add rsp, 0x38; ret;
0x0011b3ef: mov eax, ebx; add rsp, 0x20; pop rbx; ret;
*SNIP*
```
- Search for COP gadgets that perform some addition but ensure only 2 random instructions are between the ADD and CALL:
```
gadgify.exe -p "add *; call r*;" -g 2 "C:\Program Files (x86)\Microsoft\Edge\Application\124.0.2478.80\msedge.dll"
*SNIP*
0x007938be: add rcx, r12; call r13;
0x00aa6659: add [r14+0x10], r13; mov rcx, r15; call r12;
0x00aa6698: add [r14+0x18], r13; mov rcx, r15; call r12;
*SNIP*
```

