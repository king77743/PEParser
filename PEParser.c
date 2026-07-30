#include <stdio.h>
#include "pe_structures.h"

ui parser(wchar_t* Path){
    FILE *program=_wfopen(Path,L"rb");
    if (program==NULL){
        puts("Program don't open");
        return -1;
    }
    DOS_HEADER DosHeader;
    fread(&DosHeader,sizeof(DOS_HEADER),1,program);
    if(DosHeader.magic!=0x5A4D){
        puts("The signature is invalid!");
        fclose(program);
        return -1;
    }
    fseek(program,DosHeader.PE_address_in_dos,SEEK_SET);
    FILE_HDR FileHdr;
    fread(&FileHdr,sizeof(FILE_HDR),1,program);
    if (FileHdr.signature!=0x00004550){
        printf("Signature PE is invalid!");
        fclose(program);
        return -1;
    }
    us ArchMagic=0;
    fread(&ArchMagic,sizeof(us),1,program);
    if (ArchMagic==0x20B){
        puts("=== FILE IS 64-BIT ===");
        fseek(program, -2, SEEK_CUR); 
        OPTIONAL_HEADER_64 OptHdr64;
        fread(&OptHdr64, sizeof(OPTIONAL_HEADER_64), 1, program);
        printf("Entry Point RVA:  0x%X\n", OptHdr64.EntryPoint);
        printf("Import Table RVA: 0x%X\n", OptHdr64.ImportRVA);
        if (OptHdr64.SecurityRAW != 0) {
            printf("Digital Signature: SIGNED (Offset: 0x%X)\n", OptHdr64.SecurityRAW);
        } else {
            printf("Digital Signature: NOT SIGNED\n");
        }
        
    }
    else if(ArchMagic==0x10B){
        puts("=== FILE IS 32-BIT ===");
        fseek(program, -2, SEEK_CUR); 
        OPTIONAL_HEADER_32 OptHdr32;
        fread(&OptHdr32, sizeof(OPTIONAL_HEADER_32), 1, program);
        printf("Entry Point RVA:  0x%X\n", OptHdr32.EntryPoint);
        printf("Import Table RVA: 0x%X\n", OptHdr32.ImportRVA);
        if (OptHdr32.SecurityRAW != 0) {
            printf("Digital Signature: SIGNED (Offset: 0x%X)\n", OptHdr32.SecurityRAW);
        } else {
            printf("Digital Signature: NOT SIGNED\n");
        }

    }
    
}
ui main(){
    wchar_t path[261];
    fgetws(path,261,stdin);
    int i = 0;
    while (path[i] != L'\0') {
        if (path[i] == L'\n') {
            path[i] = L'\0';
            break; 
        }
        i++;
    }
    parser(path);
    return 0;
}