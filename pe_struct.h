#pragma once
#include <stdint.h>

typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef uint32_t LONG;

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
