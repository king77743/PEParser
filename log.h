#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <time.h>
#include "pe_structures.h"

void us_to_dec(unsigned short value, char* out_buf) {
    int pos = 6; 
    out_buf[pos] = '\0';
    if (value == 0) {
        out_buf[--pos] = '0';
    } else {
        while (value > 0) {
            out_buf[--pos] = '0' + (value % 10); 
            value /= 10;
        }
    }
    int start = 0;
    while (out_buf[pos] != '\0') {
        out_buf[start++] = out_buf[pos++];
    }
    out_buf[start] = '\0';
}

void HEX(void * value,uc bytes,uc* hex_buffer){
    char hex[]="0123456789ABCDEF";
    unsigned char * byte_ptr=(unsigned char*)value;
    int position=0;
    for (signed char i=bytes-1;i>=0;i--){
        unsigned char current_byte=byte_ptr[i];
        hex_buffer[position++]=hex[(current_byte>>4)&0x0F];
        hex_buffer[position++]=hex[current_byte&0x0F];
    }
    hex_buffer[position]='\0';
}

void LogFileHeader(FILE *pathtosave,FILE_HDR* FileHdr){
    char FileHdrLogBuffer[512];
    char *machine="Unknown";
    switch(FileHdr->machine){
        case 0x014C: machine = "x86 (32-bit)"; break;
        case 0x8664: machine = "x64 (64-bit)"; break;
        case 0x0200: machine = "Intel Itanium"; break;
        case 0xAA64: machine = "ARM64"; break;
        case 0x01C4: machine = "ARM (32-bit)"; break;
    }
    char time_buffer[32]="Unknown Time";
    time_t time_info=(time_t)FileHdr->Time;
    struct tm *pe_time_info = gmtime(&time_info); 
    if (pe_time_info!=NULL){
        strftime(time_buffer,sizeof(time_buffer),"%d.%m.%Y %H:%M:%S", pe_time_info);
    }
    us flags=FileHdr->characteristics;
    snprintf(FileHdrLogBuffer, sizeof(FileHdrLogBuffer),
        "+--------------------------------------------------------+\n"
        "|                  PE FILE HEADER INFO                   |\n"
        "+--------------------------------------------------------+\n"
        "  - Machine Architecture : %s\n"
        "  - Number of Sections   : %d\n"
        "  - Time Date Stamp      : %s\n"
        "  - Characteristics      : %s%s%s%s\n"
        "+--------------------------------------------------------+\n\n",
        machine, 
        FileHdr->SectionCount, 
        time_buffer,
        
        (flags & 0x2000) ? "[DLL] " : ((flags & 0x0002) ? "[EXE] " : "[Unknown] "),
        (flags & 0x0020) ? "[>2GB] " : "",
        (flags & 0x0001) ? "[NoReloc] " : "",
        (flags & 0x0200) ? "[FromSwap] " : ""
    );
    fputs(FileHdrLogBuffer,pathtosave);
}

ui RVAtoRAW(ui rva,SECTION_HEADER* section ,us sectioncount){
    if(rva<section[0].VirtualAddress){
        return rva;
    }
    for (us i=0;i<sectioncount;i++){
        if(rva>=section[i].VirtualAddress && rva<section[i].VirtualAddress+section[i].VirtualSize){
            return rva-section[i].VirtualAddress+section[i].PointerToRawData;
        }
    }
    return 0;
}

void LogOptHdr32(FILE* pathtosave, OPTIONAL_HEADER_32* OptHdr32) {
    char LogBufferOptHdr32[1280]; 
    char SigOffsetBuf[32];
    ui securityRAW=OptHdr32->SecurityRAW;
    char* subsystem = "Unknown";
    switch (OptHdr32->Subsystem) {
        case 1: subsystem = "Native (Driver)"; break;
        case 2: subsystem = "Windows GUI (Graphical)"; break;
        case 3: subsystem = "Windows CUI (Console)"; break;
    }

    if (securityRAW != 0) {
        HEX(&securityRAW, sizeof(securityRAW), SigOffsetBuf);
    }
    unsigned short chars = OptHdr32->DllCharacteristics;
    snprintf(LogBufferOptHdr32, sizeof(LogBufferOptHdr32),
        "+--------------------------------------------------------+\n"
        "|            PE32 OPTIONAL HEADER INFO (32-bit)          |\n"
        "+--------------------------------------------------------+\n"
        "  - Linker Version       : %d.%d\n"
        "  - Size of Code (Bytes) : %u\n"
        "  - Entry Point RVA      : 0x%08X\n"
        "  - Preferred Image Base : 0x%08X\n" 
        "  - Size in Memory       : %u bytes\n"
        "  - Subsystem Environment: %s\n"
        "  - Digital Signature    : %s\n"
        "  - Export Table RVA: 0x%08x\n"
        "  - Security Flags:\n"
        "    * [ASLR]       %s\n"
        "    * [DEP]        %s\n"
        "    * [SEH]        %s\n"
        "    * [Sandbox]    %s\n"
        "    * [CFG Protection] %s\n"
        "+--------------------------------------------------------+\n\n",
        OptHdr32->MajorLinker, OptHdr32->MinorLinker,
        OptHdr32->SizeOfCode,
        OptHdr32->EntryPoint,
        OptHdr32->ImageBase, 
        OptHdr32->SizeOfImage,
        subsystem,
        (securityRAW != 0) ? "SIGNED" : "NOT SIGNED",
        OptHdr32->ExportRVA,
        (chars & 0x0040) ? "Enabled (ASLR)" : "DISABLED (Vulnerable!)",
        (chars & 0x0100) ? "Enabled (DEP)"  : "DISABLED (Vulnerable!)",
        (chars & 0x0400) ? "No SEH Handlers (Immediate Crash on Error)" : "Uses Standard Exception Handling",
        (chars & 0x2000) ? "AppContainer Required (Isolated Sandbox)" : "Standard Integrity Level",
        (chars & 0x8000) ? "Active (Control Flow Guard)" : "No Control Flow Guard"
    );
    fputs(LogBufferOptHdr32, pathtosave);
    if (securityRAW != 0) {
        fputs("  [!] Digital Signature Offset (RAW): ", pathtosave);
        fputs(SigOffsetBuf, pathtosave);
        fputs("\n\n", pathtosave);
    }
}

void LogOptHdr64(FILE* pathtosave, OPTIONAL_HEADER_64* OptHdr64) {
    char LogBufferOptHdr64[1280]; 
    char SigOffsetBuf[32];
    ui securityRAW=OptHdr64->SecurityRAW;
    char* subsystem = "Unknown";
    switch (OptHdr64->Subsystem) {
        case 1: subsystem = "Native (Driver)"; break;
        case 2: subsystem = "Windows GUI (Graphical)"; break;
        case 3: subsystem = "Windows CUI (Console)"; break;
    }
    if (securityRAW != 0) {
        HEX(&securityRAW, sizeof(securityRAW), SigOffsetBuf);
    }
    us chars = OptHdr64->DllCharacteristics;
    snprintf(LogBufferOptHdr64, sizeof(LogBufferOptHdr64),
        "+--------------------------------------------------------+\n"
        "|            PE32+ OPTIONAL HEADER INFO (64-bit)         |\n"
        "+--------------------------------------------------------+\n"
        "  - Linker Version       : %d.%d\n"
        "  - Size of Code (Bytes) : %u\n"
        "  - Entry Point RVA      : 0x%08X\n"
        "  - Image Base : 0x%016llX\n" 
        "  - Size in Memory       : %u bytes\n"
        "  - Subsystem Environment: %s\n"
        "  - Digital Signature    : %s\n" 
        "  - Export Table RVA: 0x%08x\n"  
        "  - Security Flags:\n"
        "    * [ASLR]       %s\n"
        "    * [DEP]        %s\n"
        "    * [SEH]        %s\n"
        "    * [Sandbox]    %s\n"
        "    * [CFG Protection] %s\n"
        "+--------------------------------------------------------+\n\n",
        OptHdr64->MajorLinker, OptHdr64->MinorLinker,
        OptHdr64->SizeOfCode,
        OptHdr64->EntryPoint,
        OptHdr64->ImageBase, 
        OptHdr64->SizeOfImage,
        subsystem,
        (securityRAW != 0) ? "SIGNED" : "NOT SIGNED",
        OptHdr64->ExportRVA,
        (chars & 0x0040) ? "Enabled (ASLR)" : "DISABLED (Vulnerable!)",
        (chars & 0x0100) ? "Enabled (DEP)"  : "DISABLED (Vulnerable!)",
        (chars & 0x0400) ? "No SEH Handlers (Immediate Crash on Error)" : "Uses Standard Exception Handling",
        (chars & 0x2000) ? "AppContainer Required (Isolated Sandbox)" : "Standard Integrity Level",
        (chars & 0x8000) ? "Active (Control Flow Guard)" : "No Control Flow Guard"
    );
    fputs(LogBufferOptHdr64, pathtosave);
    if (securityRAW != 0) {
        fputs("  [!] Digital Signature Offset (RAW): ", pathtosave);
        fputs(SigOffsetBuf, pathtosave);
        fputs("\n\n", pathtosave);
    }
}

void ExportTableParser(uc* file_buffer, FILE* pathtosave, EXPORT_TABLE* ExportTbl, SECTION_HEADER* SectionTbl, us SectionCount, ui ExportStartRVA, ui ExportEndRVA) {
    ui FuncAddrArrayRAW = RVAtoRAW(ExportTbl->AddressOfFunctions, SectionTbl, SectionCount);
    if (!FuncAddrArrayRAW) {
        puts("Func Address Array RAW return 0!");
        return;
    }
    ui NamesAddrArrayRAW = RVAtoRAW(ExportTbl->AddressOfNames, SectionTbl, SectionCount);
    ui OrdinaAddrArrayRAW = RVAtoRAW(ExportTbl->AddressOfNameOrdinals, SectionTbl, SectionCount);
    ui DLLNameRAW = RVAtoRAW(ExportTbl->Name, SectionTbl, SectionCount);

    char* DLLName = "UNKNOWN";
    if (DLLNameRAW != 0) {
        DLLName = (char*)(file_buffer + DLLNameRAW);
    }
    ui* NameJOIN = (ui*)calloc(ExportTbl->NumberOfFunctions, sizeof(ui));
    if (NameJOIN == NULL) {
        puts("Memory allocation for Export Table failed!");
        return;
    }
    for (ui j = 0; j < ExportTbl->NumberOfNames; j++) {
        us Index = *(us*)(file_buffer + OrdinaAddrArrayRAW + (j * 2));
        ui FuncNameRVA = *(ui*)(file_buffer + NamesAddrArrayRAW + (4 * j));
        ui FuncNameRAW = RVAtoRAW(FuncNameRVA, SectionTbl, SectionCount);
        if (FuncNameRAW != 0 && Index < ExportTbl->NumberOfFunctions) {
            NameJOIN[Index] = FuncNameRAW;
        }
    }
    
    char ExportTableLogBuffer[512];
    snprintf(ExportTableLogBuffer, sizeof(ExportTableLogBuffer), 
             "Exported DLL Name: %s\n"
             "+---------+-------+------------+--------------------------------------\n"
             "| Ordinal | Index |  Func RVA  | Export Name / Forward\n"
             "+---------+-------+------------+--------------------------------------\n", 
             DLLName);
    fputs(ExportTableLogBuffer, pathtosave);

    for (ui i = 0; i < ExportTbl->NumberOfFunctions; i++) {
        ui FuncRVA = *(ui*)(file_buffer + FuncAddrArrayRAW + (i * 4));
        if (FuncRVA == 0) {
            continue;
        }
        ui Ordinal = ExportTbl->Base + i;
        
        if (FuncRVA >= ExportStartRVA && FuncRVA < ExportEndRVA) {
            ui ForwardNameRAW = RVAtoRAW(FuncRVA, SectionTbl, SectionCount);
            if (ForwardNameRAW == 0) {
                snprintf(ExportTableLogBuffer, sizeof(ExportTableLogBuffer), 
                         "| %-7u | %-5u | 0x%08X | [ERROR: Invalid Forward RVA]\n", Ordinal, i, FuncRVA);
            } else {
                snprintf(ExportTableLogBuffer, sizeof(ExportTableLogBuffer), 
                         "| %-7u | %-5u | 0x%08X | [FWD] %s\n", Ordinal, i, FuncRVA, (char*)(file_buffer + ForwardNameRAW));
            }
            fputs(ExportTableLogBuffer, pathtosave);
            continue;
        }
        
        char* pFuncName = "[Ordinal Only / No Name]";
        ui FuncNameRAW = NameJOIN[i];
        if (FuncNameRAW != 0) {
            pFuncName = (char*)(file_buffer + FuncNameRAW);
        }
        
        fprintf(pathtosave, "| %-7u | %-5u | 0x%08X | ", Ordinal, i, FuncRVA);
        fputs(pFuncName, pathtosave);
        fputs("\n", pathtosave);
    }
    fputs("+---------+-------+------------+--------------------------------------\n", pathtosave);
    free(NameJOIN);
}

ui SectionTableParser(FILE* pathtosave, SECTION_HEADER* SectionTable, us SectionCount, char* section_buffer_size, ui buffer_size) {
    if (!pathtosave || !SectionTable || !section_buffer_size || buffer_size == 0) return -1;
    ui char_written = 0, bytes = 0;
    bytes = (ui)snprintf(section_buffer_size + char_written, buffer_size - char_written,
        "+-----+----------+-------------------+-------------------+\n"
        "|  #  |   Name   |    Virtual RVA    |     Raw Offset    |\n"
        "+-----+----------+-------------------+-------------------+\n");
    if (bytes >= (buffer_size - char_written)) return -1;
    char_written += bytes;
    for (us SectionNow = 0; SectionNow < SectionCount; SectionNow++) {
        ui space = buffer_size - char_written;
        bytes = (ui)snprintf(section_buffer_size + char_written, space,
            "| %-3d | %-8.8s |    0x%08X     |    0x%08X     |\n", 
            SectionNow + 1, SectionTable[SectionNow].name, 
            SectionTable[SectionNow].VirtualAddress, SectionTable[SectionNow].PointerToRawData);
        if (bytes >= space) return -1;
        char_written += bytes;
    }
    bytes = (ui)snprintf(section_buffer_size + char_written, buffer_size - char_written,
        "+-----+----------+-------------------+-------------------+\n\n");
    if (bytes >= (buffer_size - char_written)) return -1;
    fputs(section_buffer_size, pathtosave);
    return 0;
}



#endif 
