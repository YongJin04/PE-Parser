#pragma once
#include <stdint.h>

typedef uint8_t BYTE;
typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef uint64_t QWORD;
typedef uint32_t LONG;
typedef uint64_t ULONGLONG;

typedef struct {
    WORD   MZSignature;
    WORD   UsedBytesInTheLastPage;
    WORD   FileSizeInPages;
    WORD   NumberOfRelocationItems;
    WORD   HeaderSizeInParagraphs;
    WORD   MinimumExtraParagraphs;
    WORD   MaximumExtraParagraphs;
    WORD   InitialRelativeSS;
    WORD   InitialSP;
    WORD   Checksum;
    WORD   InitialIP;
    WORD   InitialRelativeCS;
    WORD   AddressOfRelocationTable;
    WORD   OverlayNumber;
    WORD   Reserved[4];
    WORD   OEMid;
    WORD   OEMinfo;
    WORD   Reserved2[10];
    LONG   AddressOfNewExeHeader;
} IMAGE_DOS_HEADER;
extern IMAGE_DOS_HEADER gDosHdr;

typedef struct {
    WORD Machine;
    WORD NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD SizeOfOptionalHeader;
    WORD Characteristics;
} IMAGE_FILE_HEADER;
extern IMAGE_FILE_HEADER gFileHdr;

static const char* getMachineName(unsigned short m) {
    switch (m) {
    case 0x0000: return "0x0000 (Unknown)";
    case 0x014C: return "0x014C (Intel 386 - x86)";
    case 0x0162: return "0x0162 (MIPS R3000)";
    case 0x0166: return "0x0166 (MIPS R4000)";
    case 0x0168: return "0x0168 (MIPS R10000)";
    case 0x0169: return "0x0169 (MIPS WCE v2)";
    case 0x0184: return "0x0184 (Alpha AXP)";
    case 0x01A2: return "0x01A2 (Hitachi SH3)";
    case 0x01A3: return "0x01A3 (Hitachi SH3 DSP)";
    case 0x01A4: return "0x01A4 (Hitachi SH3E)";
    case 0x01A6: return "0x01A6 (Hitachi SH4)";
    case 0x01A8: return "0x01A8 (Hitachi SH5)";
    case 0x01C0: return "0x01C0 (ARM)";
    case 0x01C2: return "0x01C2 (ARM Thumb)";
    case 0x01C4: return "0x01C4 (ARM NT)";
    case 0x01D3: return "0x01D3 (Matsushita AM33)";
    case 0x01F0: return "0x01F0 (PowerPC)";
    case 0x01F1: return "0x01F1 (PowerPC FP)";
    case 0x0200: return "0x0200 (Intel Itanium - IA64)";
    case 0x0266: return "0x0266 (MIPS16)";
    case 0x0284: return "0x0284 (Alpha64)";
    case 0x0366: return "0x0366 (MIPS FPU)";
    case 0x0466: return "0x0466 (MIPS16 with FPU)";
    case 0x0520: return "0x0520 (Infineon TriCore)";
    case 0x0CEF: return "0x0CEF (CEF)";
    case 0x0EBC: return "0x0EBC (EFI Byte Code)";
    case 0x5032: return "0x5032 (RISC-V 32-bit)";
    case 0x5064: return "0x5064 (RISC-V 64-bit)";
    case 0x5128: return "0x5128 (RISC-V 128-bit)";
    case 0x8664: return "0x8664 (AMD x86-64)";
    case 0x9041: return "0x9041 (Mitsubishi M32R)";
    case 0xAA64: return "0xAA64 (ARM64)";
    case 0xC0EE: return "0xC0EE (CEE)";
    default: return "Unknown Machine Type";
    }
}

static void showFileCharacteristics(WORD ch) {
    if (ch & 0x0001) printf("             - IMAGE_FILE_RELOCS_STRIPPED\n");
    if (ch & 0x0002) printf("             - IMAGE_FILE_EXECUTABLE_IMAGE\n");
    if (ch & 0x0004) printf("             - IMAGE_FILE_LINE_NUMS_STRIPPED\n");
    if (ch & 0x0008) printf("             - IMAGE_FILE_LOCAL_SYMS_STRIPPED\n");
    if (ch & 0x0010) printf("             - IMAGE_FILE_AGGRESIVE_WS_TRIM\n");
    if (ch & 0x0020) printf("             - IMAGE_FILE_LARGE_ADDRESS_AWARE\n");
    if (ch & 0x0080) printf("             - IMAGE_FILE_BYTES_REVERSED_LO\n");
    if (ch & 0x0100) printf("             - IMAGE_FILE_32BIT_MACHINE\n");
    if (ch & 0x0200) printf("             - IMAGE_FILE_DEBUG_STRIPPED\n");
    if (ch & 0x0400) printf("             - IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP\n");
    if (ch & 0x0800) printf("             - IMAGE_FILE_NET_RUN_FROM_SWAP\n");
    if (ch & 0x1000) printf("             - IMAGE_FILE_SYSTEM\n");
    if (ch & 0x2000) printf("             - IMAGE_FILE_DLL\n");
    if (ch & 0x4000) printf("             - IMAGE_FILE_UP_SYSTEM_ONLY\n");
    if (ch & 0x8000) printf("             - IMAGE_FILE_BYTES_REVERSED_HI\n");
}

static const char* getOptionalMagicName(WORD magic) {
    switch (magic) {
    case 0x10B: return "PE32";
    case 0x20B: return "PE64";
    case 0x107: return "ROM";
    default: return "Unknown";
    }
}

static const char* getImageSubsystemName(unsigned short subsystem) {
    switch (subsystem) {
    case 0:  return "IMAGE_SUBSYSTEM_UNKNOWN";
    case 1:  return "NATIVE";
    case 2:  return "WINDOWS_GUI";
    case 3:  return "WINDOWS_CUI";
    case 5:  return "OS2_CUI";
    case 7:  return "POSIX_CUI";
    case 8:  return "NATIVE_WINDOWS";
    case 9:  return "WINDOWS_CE_GUI";
    case 10: return "EFI_APPLICATION";
    case 11: return "EFI_BOOT_SERVICE_DRIVER";
    case 12: return "EFI_RUNTIME_DRIVER";
    case 13: return "EFI_ROM";
    case 14: return "XBOX";
    case 16: return "WINDOWS_BOOT_APPLICATION";
    default: return "Unknown Subsystem";
    }
}

static void showDllCharacteristics(WORD ch) {
    if (ch & 0x0001) printf("             - IMAGE_LIBRARY_PROCESS_INIT\n");
    if (ch & 0x0002) printf("             - IMAGE_LIBRARY_PROCESS_TERM\n");
    if (ch & 0x0004) printf("             - IMAGE_LIBRARY_THREAD_INIT\n");
    if (ch & 0x0008) printf("             - IMAGE_LIBRARY_THREAD_TERM\n");
    if (ch & 0x0020) printf("             - IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA\n");
    if (ch & 0x0040) printf("             - IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (ASLR)\n");
    if (ch & 0x0080) printf("             - IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY\n");
    if (ch & 0x0100) printf("             - IMAGE_DLLCHARACTERISTICS_NX_COMPAT\n");
    if (ch & 0x0200) printf("             - IMAGE_DLLCHARACTERISTICS_NO_ISOLATION\n");
    if (ch & 0x0400) printf("             - IMAGE_DLLCHARACTERISTICS_NO_SEH\n");
    if (ch & 0x0800) printf("             - IMAGE_DLLCHARACTERISTICS_NO_BIND\n");
    if (ch & 0x2000) printf("             - IMAGE_DLLCHARACTERISTICS_WDM_DRIVER\n");
    if (ch & 0x8000) printf("             - IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE\n");
}

typedef struct {
    WORD Magic;
    BYTE MajorLinkerVersion;
    BYTE MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    DWORD BaseOfData;
    DWORD ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD MajorOperatingSystemVersion;
    WORD MinorOperatingSystemVersion;
    WORD MajorImageVersion;
    WORD MinorImageVersion;
    WORD MajorSubsystemVersion;
    WORD MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD Subsystem;
    WORD DllCharacteristics;
    DWORD SizeOfStackReserve;
    DWORD SizeOfStackCommit;
    DWORD SizeOfHeapReserve;
    DWORD SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
} IMAGE_OPTIONAL_HEADER32;
extern IMAGE_OPTIONAL_HEADER32 gOptionalHdr32;

typedef struct {
    WORD Magic;
    BYTE MajorLinkerVersion;
    BYTE MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    ULONGLONG ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD MajorOperatingSystemVersion;
    WORD MinorOperatingSystemVersion;
    WORD MajorImageVersion;
    WORD MinorImageVersion;
    WORD MajorSubsystemVersion;
    WORD MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD Subsystem;
    WORD DllCharacteristics;
    ULONGLONG SizeOfStackReserve;
    ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
} IMAGE_OPTIONAL_HEADER64;
extern IMAGE_OPTIONAL_HEADER64 gOptionalHdr64;

static const char* directoryNames[] = {
    "Export                               ",
    "Import                               ",
    "Resource                             ",
    "Exception                            ",
    "Security                             ",
    "BaseRelocationTable                  ",
    "DebugDirectory                       ",
    "CopyrightOrArchitectureSpecificData  ",
    "GlobalPtr                            ",
    "TLSDirectory                         ",
    "LoadConfigurationDirectory           ",
    "BoundImportDirectory                 ",
    "ImportAddressTable                   ",
    "DelayLoadImportDescriptors           ",
    "COMRuntimedescriptor                 ",
    "Reserved                             "
};

typedef struct {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY;
extern IMAGE_DATA_DIRECTORY gDataDirectory[16];

static void showSectionCharacteristics(DWORD ch) {
    if (ch & 0x00000008) printf("         - IMAGE_SCN_TYPE_NO_PAD\n");
    if (ch & 0x00000020) printf("         - IMAGE_SCN_CNT_CODE\n");
    if (ch & 0x00000040) printf("         - IMAGE_SCN_CNT_INITIALIZED_DATA\n");
    if (ch & 0x00000080) printf("         - IMAGE_SCN_CNT_UNINITIALIZED_DATA\n");
    if (ch & 0x00000100) printf("         - IMAGE_SCN_LNK_OTHER\n");
    if (ch & 0x00000200) printf("         - IMAGE_SCN_LNK_INFO\n");
    if (ch & 0x00000800) printf("         - IMAGE_SCN_LNK_REMOVE\n");
    if (ch & 0x00001000) printf("         - IMAGE_SCN_LNK_COMDAT\n");
    if (ch & 0x00008000) printf("         - IMAGE_SCN_GPREL\n");
    if (ch & 0x00020000) printf("         - IMAGE_SCN_MEM_16BIT\n");
    if (ch & 0x00040000) printf("         - IMAGE_SCN_MEM_LOCKED\n");
    if (ch & 0x00080000) printf("         - IMAGE_SCN_MEM_PRELOAD\n");
    if (ch & 0x00100000) printf("         - IMAGE_SCN_ALIGN_1BYTES\n");
    if (ch & 0x00200000) printf("         - IMAGE_SCN_ALIGN_2BYTES\n");
    if (ch & 0x00400000) printf("         - IMAGE_SCN_ALIGN_8BYTES\n");
    if (ch & 0x00800000) printf("         - IMAGE_SCN_ALIGN_128BYTES\n");
    if (ch & 0x01000000) printf("         - IMAGE_SCN_LNK_NRELOC_OVFL\n");
    if (ch & 0x02000000) printf("         - IMAGE_SCN_MEM_DISCARDABLE\n");
    if (ch & 0x04000000) printf("         - IMAGE_SCN_MEM_NOT_CACHED\n");
    if (ch & 0x08000000) printf("         - IMAGE_SCN_MEM_NOT_PAGED\n");
    if (ch & 0x10000000) printf("         - IMAGE_SCN_MEM_SHARED\n");
    if (ch & 0x20000000) printf("         - IMAGE_SCN_MEM_EXECUTE\n");
    if (ch & 0x40000000) printf("         - IMAGE_SCN_MEM_READ\n");
    if (ch & 0x80000000) printf("         - IMAGE_SCN_MEM_WRITE\n");
}

typedef struct {
    BYTE Name[8];
    DWORD VirtualSize;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD Characteristics;
} IMAGE_SECTION_HEADER;
extern IMAGE_SECTION_HEADER gSectionHeader;

typedef struct {
    DWORD   OriginalFirstThunk;
    DWORD   TimeDateStamp;
    DWORD   ForwarderChain;
    DWORD   Name;
    DWORD   FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;
extern IMAGE_IMPORT_DESCRIPTOR gImportDescriptor;

typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;
    DWORD   AddressOfNames;
    DWORD   AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY;
extern IMAGE_EXPORT_DIRECTORY gExportDirectory;
