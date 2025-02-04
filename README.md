# PE Parser

## Overview
This project is a PE (Portable Executable) file parser written in C. It analyzes and extracts key information from PE files, including DOS headers, NT headers, section headers, and import/export tables.

## Features
- Parses PE file structure, including:
  - DOS Header
  - NT Header
  - Section Headers
  - Import Table
  - Export Table
- Extracts detailed information about the file's characteristics.
- Supports both 32-bit and 64-bit PE files.
- Displays import and export symbols from DLLs.

## Key Functions
### `processFile(const char* path)`
- Opens and reads the PE file.
- Calls various parsing functions to extract data.

### `parseDosHeader(FILE* filePtr)`
- Reads and verifies the DOS header.
- Checks for the MZ signature to confirm the file type.

### `parseNtHeader(FILE* filePtr)`
- Reads and verifies the NT header.
- Extracts key information such as machine type, entry point, and image base.

### `parseSectionHeader(FILE* filePtr)`
- Reads section headers and extracts section characteristics.

### `parseImportAddressTable(FILE* filePtr)`
- Extracts import table information.
- Displays DLLs and their imported functions.

### `parseExportAddressTable(FILE* filePtr)`
- Extracts export table information.
- Lists exported functions from the PE file.

## Usage
To use the PE parser, compile the source code and run it with the `-f` option followed by the PE file path:
```sh
./pe_parser -f <file_path>
```

## Example Output
```sh
 - Dos Header
     - MZ Signature                  : 0x5A4D
     - Address of New EXE Header     : 0xF0

 - Dos STUB
     - Dos STUB (ASCII)              : This program cannot be run in DOS mode.
     - RICH Header Exists.

 - NT Header
     - Signature                     : 0x50450000 ('PE  ')
     - File Header
         - Machine                   : 0x0x8664 (AMD x86-64)
         - Number of Sections        : 0x8
         - Time DateStamp            : 2016-03-18 23:39:13
         - Pointer To SymbolTable    : 0x0
         - Number Of Symbols         : 0x0
         - Size of Optional Header   : 0xF0
         - Characteristics           : 0x2022
             - IMAGE_FILE_EXECUTABLE_IMAGE
             - IMAGE_FILE_LARGE_ADDRESS_AWARE
             - IMAGE_FILE_DLL
     - Optional Header
         - Optional Header Signature : 0x20B (PE64)
         - Major Linker Version      : 0xE
         - Minor Linker Version      : 0x26
         - Size Of Code              : 0x86000
         - Size Of Initialized Data  : 0x41000
         - Size Of Uninitialized Data: 0x0
         - Address Of Entry Point    : 0x2E120
         - Base Of Code              : 0x1000
         - Image Base                : 0x180000000
         - Section Alignment         : 0x1000
         - File Alignment            : 0x1000
         - Major OS Version          : 0xA
         - Minor OS Version          : 0x0
         - Major Image Version       : 0xA
         - Minor Image Version       : 0x0
         - Major Subsystem Version   : 0xA
         - Minor Subsystem Version   : 0x0
         - Win32 Version Value       : 0x0
         - Size Of Image             : 0xC8000
         - Size Of Headers           : 0x1000
         - Check Sum                 : 0xD237B
         - Subsystem                 : 0x3 (WINDOWS_CUI)
         - Dll Characteristics       : 0x4160
             - IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
             - IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (ASLR)
             - IMAGE_DLLCHARACTERISTICS_NX_COMPAT
         - Size Of Stack Reserve     : 0x40000
         - Size Of Stack Commit      : 0x1000
         - Size Of Heap Reserve      : 0x100000
         - Size Of Heap Commit       : 0x1000
         - Loader Flags              : 0x0
         - Number Of RVA And Sizes   : 0x10
         - Data Directory
             - Export                                (RVA : 0xA3F90 / Virtual Size : 0xEB68)
             - Import                                (RVA : 0xB2AF8 / Virtual Size : 0x820)
             - Resource                              (RVA : 0xC6000 / Virtual Size : 0x520)
             - Exception                             (RVA : 0xC0000 / Virtual Size : 0x4740)
             - Security                              (RVA : 0xC7000 / Virtual Size : 0x4228)
             - BaseRelocationTable                   (RVA : 0xC7000 / Virtual Size : 0x464)
             - DebugDirectory                        (RVA : 0x9D284 / Virtual Size : 0x70)
             - LoadConfigurationDirectory            (RVA : 0x88C40 / Virtual Size : 0x140)
             - ImportAddressTable                    (RVA : 0x88D80 / Virtual Size : 0x2AC8)
             - DelayLoadImportDescriptors            (RVA : 0xA3A78 / Virtual Size : 0x80)

 - Section Header
     - Name                          : .text
     - Virtual Size                  : 0x84004
     - Virtual Address               : 0x1000
     - Size of Raw Data              : 0x85000
     - Pointer to Raw Data           : 0x1000
     - Pointer to Relocations        : 0x0
     - Pointer to Line Numbers       : 0x0
     - Number of Relocations         : 0x0
     - Number of Line Numbers        : 0x0
     - Characteristics               : 0x60000020
         - IMAGE_SCN_CNT_CODE
         - IMAGE_SCN_MEM_EXECUTE
         - IMAGE_SCN_MEM_READ

     - Name                          : fothk
     - Virtual Size                  : 0x1000
     - Virtual Address               : 0x86000
     - Size of Raw Data              : 0x1000
     - Pointer to Raw Data           : 0x86000
     - Pointer to Relocations        : 0x0
     - Pointer to Line Numbers       : 0x0
     - Number of Relocations         : 0x0
     - Number of Line Numbers        : 0x0
     - Characteristics               : 0x60000020
         - IMAGE_SCN_CNT_CODE
         - IMAGE_SCN_MEM_EXECUTE
         - IMAGE_SCN_MEM_READ

     - Name                          : .rdata
     - Virtual Size                  : 0x36C3A
     - Virtual Address               : 0x87000
     - Size of Raw Data              : 0x37000
     - Pointer to Raw Data           : 0x87000
     - Pointer to Relocations        : 0x0
     - Pointer to Line Numbers       : 0x0
     - Number of Relocations         : 0x0
     - Number of Line Numbers        : 0x0
     - Characteristics               : 0x40000040
         - IMAGE_SCN_CNT_INITIALIZED_DATA
         - IMAGE_SCN_MEM_READ

     - Name                          : .data
     - Virtual Size                  : 0x1450
     - Virtual Address               : 0xBE000
     - Size of Raw Data              : 0x1000
     - Pointer to Raw Data           : 0xBE000
     - Pointer to Relocations        : 0x0
     - Pointer to Line Numbers       : 0x0
     - Number of Relocations         : 0x0
     - Number of Line Numbers        : 0x0
     - Characteristics               : 0xC0000040
         - IMAGE_SCN_CNT_INITIALIZED_DATA
         - IMAGE_SCN_MEM_READ
         - IMAGE_SCN_MEM_WRITE

     - Name                          : .pdata
     - Virtual Size                  : 0x4740
     - Virtual Address               : 0xC0000
     - Size of Raw Data              : 0x5000
     - Pointer to Raw Data           : 0xBF000
     - Pointer to Relocations        : 0x0
     - Pointer to Line Numbers       : 0x0
     - Number of Relocations         : 0x0
     - Number of Line Numbers        : 0x0
     - Characteristics               : 0x40000040
         - IMAGE_SCN_CNT_INITIALIZED_DATA
         - IMAGE_SCN_MEM_READ

     - Name                          : .didat
     - Virtual Size                  : 0xA8
     - Virtual Address               : 0xC5000
     - Size of Raw Data              : 0x1000
     - Pointer to Raw Data           : 0xC4000
     - Pointer to Relocations        : 0x0
     - Pointer to Line Numbers       : 0x0
     - Number of Relocations         : 0x0
     - Number of Line Numbers        : 0x0
     - Characteristics               : 0xC0000040
         - IMAGE_SCN_CNT_INITIALIZED_DATA
         - IMAGE_SCN_MEM_READ
         - IMAGE_SCN_MEM_WRITE

     - Name                          : .rsrc
     - Virtual Size                  : 0x520
     - Virtual Address               : 0xC6000
     - Size of Raw Data              : 0x1000
     - Pointer to Raw Data           : 0xC5000
     - Pointer to Relocations        : 0x0
     - Pointer to Line Numbers       : 0x0
     - Number of Relocations         : 0x0
     - Number of Line Numbers        : 0x0
     - Characteristics               : 0x40000040
         - IMAGE_SCN_CNT_INITIALIZED_DATA
         - IMAGE_SCN_MEM_READ

     - Name                          : .reloc
     - Virtual Size                  : 0x4BC
     - Virtual Address               : 0xC7000
     - Size of Raw Data              : 0x1000
     - Pointer to Raw Data           : 0xC6000
     - Pointer to Relocations        : 0x0
     - Pointer to Line Numbers       : 0x0
     - Number of Relocations         : 0x0
     - Number of Line Numbers        : 0x0
     - Characteristics               : 0x42000040
         - IMAGE_SCN_CNT_INITIALIZED_DATA
         - IMAGE_SCN_MEM_DISCARDABLE
         - IMAGE_SCN_MEM_READ

 - Section
     - .idata
         - Import Descriptor
             - DLL Name : MSVCP140D.dll
                 - Import Symbol Name : ?uncaught_exception@std@@YA_NXZ
                 - Import Symbol Name : ?good@ios_base@std@@QEBA_NXZ
                                  (Some omissions)
                 - Import Symbol Name : ?flags@ios_base@std@@QEBAHXZ
                 - Import Symbol Name : ?width@ios_base@std@@QEBA_JXZ
     - .rdata
         - Export Descriptor
             - DLL Name : KERNEL32.dll
                 - Export Symbol Name : AcquireSRWLockExclusive
                 - Export Symbol Name : AcquireSRWLockShared
                                  (Some omissions)
                 - Export Symbol Name : ActivateActCtx
                 - Export Symbol Name : ActivateActCtxWorker
```
This output confirms that the PE parser successfully extracts import and export information from PE files.
