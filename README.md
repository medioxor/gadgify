## Gadgify

Gadgify is a fast and simplified gadget enumeration tool for x86_64
binaries with flexible functionality to make filtering for specific gadgets
a breeze. Gadgify can be used to find ROP, JOP, COP, and COOP gadgets by querying
for sequences of instructions using a simplified regex based search. Prebuilt binaries
for Windows and Linux can be found via the following URL:
- https://github.com/medioxor/gadgify/releases

## Features
- Supports x86-64/ARM/AARCH64/ARM-Thumb-2 Portable Executables (PE)
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
Usage: Gadgify [--help] [--version] [--no-cet] [--gap VAR] --pattern VAR {bin,dir,raw}

Optional arguments:
  -h, --help     shows help message and exits
  -v, --version  prints version information and exits
  -nc, --no-cet  Only search for gadgets in executable code that is NOT compatible with Intel CET.
  -g, --gap      The gap between instructions specified in the pattern e.g. searching for the 'mov r*, r1*;call r*;sub *' pattern with a gap of '3' will result in gadgets that can have up to 3 instructions that do not match the pattern between each instruction in the pattern provided. [nargs=0..1] [default: 3]
  -p, --pattern  The pattern to search for. [required]

Subcommands:
  bin           Search for gadgets in a binary file e.g. PE, ELF, MACHO.
  dir           Search for gadgets in every binary found within a given directory.
  raw           Search for gadgets in raw executable code e.g. a dumped .text section.
```

## Usage examples
- Search for ROP gadgets but ensure up to 3 random instructions preceded the return instruction:
```
gadgify.exe -g 3 -p "ret;" bin C:\Windows\system32\ntdll.dll
*SNIP*
ntdll.dll+0x0011920b: mov eax, 1; ret;
ntdll.dll+0x0011b3ef: mov eax, ebx; add rsp, 0x20; pop rbx; ret;
ntdll.dll+0x00119243: xor eax, eax; add rsp, 0x28; ret;
ntdll.dll+0x0011b440: mov eax, ebx; add rsp, 0x20; pop rbx; ret;
ntdll.dll+0x0011b5ac: pop r14; pop rdi; pop rsi; ret;
ntdll.dll+0x00119844: pop rdi; pop rsi; pop rbp; ret;
ntdll.dll+0x001199c6: mov rsi, qword ptr [rsp + 0x48]; add rsp, 0x20; pop rdi; ret;
ntdll.dll+0x001199e5: setne cl; mov eax, ecx; add rsp, 0x28; ret;
ntdll.dll+0x00119cba: pop rdi; pop rsi; pop rbp; ret;
ntdll.dll+0x00119f97: pop r14; pop rdi; pop rbp; ret;
ntdll.dll+0x0011a0c6: pop r15; pop r14; pop r12; ret;
ntdll.dll+0x0011c0a0: mov rdi, qword ptr [rsp + 0x48]; add rsp, 0x20; pop r14; ret;
ntdll.dll+0x0011c16c: mov qword ptr [r10], r8; xor eax, eax; ret;
*SNIP*
```
- Search for COP gadgets that perform some addition but ensure only 2 random instructions are between the ADD and CALL:
```
gadgify.exe -p "add *; call r*;" -g 2 bin "C:\Program Files (x86)\Microsoft\Edge\Application\124.0.2478.80\msedge.dll"
*SNIP*
0x007938be: add rcx, r12; call r13;
0x00aa6659: add [r14+0x10], r13; mov rcx, r15; call r12;
0x00aa6698: add [r14+0x18], r13; mov rcx, r15; call r12;
*SNIP*
```
- Search for ROP gadgets in every binary in System32 that are not compatible with Intel CET:
```
gadgify.exe -nc -p "ret;" dir C:\Windows\system32\
*SNIP*
acproxy.dll+0x0000226a: mov eax, dword ptr [rbp + 0x90]; add rsp, 0x20; pop rbp; ret;
acproxy.dll+0x000022d0: mov eax, dword ptr [rbp + 0xa0]; add rsp, 0x20; pop rbp; ret;
acproxy.dll+0x000022ef: mov dword ptr [rip + 0x1d07], 0xffffffff; add rsp, 0x20; pop rbp; ret;
acproxy.dll+0x00002327: mov eax, ecx; add rsp, 0x20; pop rbp; ret;
Searching for gadgets in ActiveSyncProvider.dll
Binary is compatible with Intel CET, not going to search for gadgets.
Searching for gadgets in aadtb.dll
aadtb.dll+0x000010b0: add rsp, 0x58; ret;
aadtb.dll+0x000011cd: add rsp, 0xa8; ret;
aadtb.dll+0x0000135c: add rsp, 0xb8; ret;
aadtb.dll+0x000013ec: add rsp, 0x48; ret;
aadtb.dll+0x0000149c: mov rsi, qword ptr [rsp + 0x60]; add rsp, 0x40; pop rdi; ret;
*SNIP*
```

## Credits
I took some inspiration and ideas from the following projects:
- https://github.com/0vercl0k/rp by https://twitter.com/0vercl0k
- https://github.com/Ben-Lichtman/ropr by https://twitter.com/_B_3_N_N_Y_

