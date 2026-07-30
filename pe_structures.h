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
    uc garbage1[14];
    ui EntryPoint;
    ui BaseOfCode;
    u64 ImageBase;
    uc garbage2[80];
    ui ExportRVA;
    ui ExportSize;
    ui ImportRVA;
    ui ImportSize;
    uc garbage3[16];
    ui SecurityRAW;
    ui SecuritySize;
    uc garbage4[88];
} OPTIONAL_HEADER_64;

typedef struct {
    us magic;
    uc garbage1[14];
    ui EntryPoint;
    ui BaseOfCode;
    ui BaseOfData;
    ui ImageBase;
    uc garbage2[64];
    ui ExportRVA;
    ui ExportSize;
    ui ImportRVA;
    ui ImportSize;
    uc garbage3[16];
    ui SecurityRAW;
    ui SecuritySize;
    uc garbage4[88];
} OPTIONAL_HEADER_32;

typedef struct {
    uc name[8];             
    ui VirtualSize;         
    ui VirtualAddress;     
    ui RawSize;             
    ui PointerToRawData;    
    uc garbage[12];         
} SECTION_HEADER;
#pragma pack(pop) 

#endif 
