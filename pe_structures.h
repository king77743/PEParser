#ifndef PE_STRUCTURES_H
#define PE_STRUCTURES_H

typedef unsigned int   ui;  
typedef unsigned short us;   
typedef unsigned char  uc; 
typedef unsigned long long u64;  

#pragma pack(push, 1) 
typedef struct {
    us magic;
    uc garbage[58];
    ui PE_address_in_dos;
} DOS_HEADER;

typedef struct {
    ui signature;
    us machine;
    us SectionCount;
    ui Time;
    ui PtrtoSymbolTable;
    ui NumbOfSymbols;
    us SizeOfOptinalHeader;
    us characteristics;
} FILE_HDR;

typedef struct {
    us magic;
    uc MajorLinker;
    uc MinorLinker;
    ui SizeOfCode;
    ui SizeOfInitializedData;
    ui SizeOfUninitializedData;
    ui EntryPoint;
    ui BaseOfCode;
    u64 ImageBase;
    ui SectionAlignment;
    ui FileAligment;
    us MajorOS;
    us MinorOs;
    us MajorImage;
    us MinorImage;
    us MajorSubsystem;
    us MinorSubsystem;
    ui Win32VersionValue;
    ui SizeOfImage;
    ui SizeOfHeaders;
    ui Checksum;
    us Subsystem;
    us DllCharacteristics;
    u64 SizeOfStackReserve;
    u64 SizeOfStackCommit;
    u64 SizeOfHeapReserve;
    u64 SizeOfHeapCommit;
    ui LoaderFlags;
    ui NumberOfRvaAndSizes;
    ui ExportRVA;
    ui ExportSize;
    ui ImportRVA;
    ui ImportSize;
    ui ResourceRVA;
    ui ResourceSize;
    ui ExcteptionRVA;
    ui ExcteptionSize;
    ui SecurityRAW;
    ui SecuritySize;
    ui BaseRelocationTableRVA;
    ui BaseRelocationTableSize;
    ui DebugRVA;
    ui DebugSize;
    ui ArchitectureSpecificDataRVA;
    ui ArchitectureSpecificDataSize;
    ui GlobalPRTRVA;
    ui GlobalPTRSize;
    ui TLSDirectoryRVA;
    ui TLSDirectorySize;
    ui LoadConfigurationDirectoryRVA;
    ui LoadConfigurationDirectorySize;
    ui BoundImportDirectoryRVA;
    ui BoundImportDirectorySize;
    ui ImportAddressTableRVA;
    ui ImportAddressTableSize;
    ui DelayLoadImportDescriptorsRVA;
    ui DelayLoadImportDescriptorsSize;
    ui NET_RVA;
    ui NET_Size;
    uc garbage[8];
} OPTIONAL_HEADER_64;

typedef struct {
    us magic;
    uc MajorLinker;
    uc MinorLinker;
    ui SizeOfCode;
    ui SizeOfInitializedData;
    ui SizeOfUninitializedData;
    ui EntryPoint;
    ui BaseOfCode;
    ui BaseOfData;
    ui ImageBase;
    ui SectionAlignment;
    ui FileAligment;
    us MajorOS;
    us MinorOs;
    us MajorImage;
    us MinorImage;
    us MajorSubsystem;
    us MinorSubsystem;
    ui Win32VersionValue;
    ui SizeOfImage;
    ui SizeOfHeaders;
    ui Checksum;
    us Subsystem;
    us DllCharacteristics;
    ui SizeOfStackReserve;
    ui SizeOfStackCommit;
    ui SizeOfHeapReserve;
    ui SizeOfHeapCommit;
    ui LoaderFlags;
    ui NumberOfRvaAndSizes;
    ui ExportRVA;
    ui ExportSize;
    ui ImportRVA;
    ui ImportSize;
    ui ResourceRVA;
    ui ResourceSize;
    ui ExcteptionRVA;
    ui ExcteptionSize;
    ui SecurityRAW;
    ui SecuritySize;
    ui BaseRelocationTableRVA;
    ui BaseRelocationTableSize;
    ui DebugRVA;
    ui DebugSize;
    ui ArchitectureSpecificDataRVA;
    ui ArchitectureSpecificDataSize;
    ui GlobalPRTRVA;
    ui GlobalPTRSize;
    ui TLSDirectoryRVA;
    ui TLSDirectorySize;
    ui LoadConfigurationDirectoryRVA;
    ui LoadConfigurationDirectorySize;
    ui BoundImportDirectoryRVA;
    ui BoundImportDirectorySize;
    ui ImportAddressTableRVA;
    ui ImportAddressTableSize;
    ui DelayLoadImportDescriptorsRVA;
    ui DelayLoadImportDescriptorsSize;
    ui NET_RVA;
    ui NET_Size;
    uc garbage[8];
} OPTIONAL_HEADER_32;

typedef struct {
    uc name[8];             
    ui VirtualSize;         
    ui VirtualAddress;     
    ui RawSize;             
    ui PointerToRawData;    
    ui PointerToRelocations;
    ui PointerToLinenumbers;
    us NumberOfRelocations;
    us NumberOfLinenumbers;
    ui Characteristics;
} SECTION_HEADER;

typedef struct{
    ui OriginalFirstThunk;
    ui TimeDateStamp;
    ui ForwarderChain;
    ui Name;
    ui FirstThunk;
}IMPORT_TABLE;

typedef struct {
    ui Characteristics;      
    ui TimeDateStamp;        
    us MajorVersion;         
    us MinorVersion;         
    ui Name;                 
    ui Base;                 
    ui NumberOfFunctions;    
    ui NumberOfNames;        
    ui AddressOfFunctions;   
    ui AddressOfNames;       
    ui AddressOfNameOrdinals;
} EXPORT_TABLE;

#pragma pack(pop) 

#endif 
