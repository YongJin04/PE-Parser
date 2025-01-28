typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef uint32_t LONG;

// IMAGE_DOS_HEADER Structure Definition
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
extern IMAGE_DOS_HEADER dosHeader;

// IMAGE_DOS_HEADER Structure Definition
