#include <stdio.h>
#include "pe_structures.h"

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
ui parser(wchar_t* Path){
    ui ImportRVA=0;
    us is64=0;
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
        puts("Signature PE is invalid!");
        fclose(program);
        return -1;
    }
    us ArchMagic=0;
    fread(&ArchMagic,sizeof(us),1,program);
    if (ArchMagic==0x20B){
        is64=1;
        puts("\t=== FILE IS 64-BIT ===\n");
        fseek(program, -2, SEEK_CUR); 
        OPTIONAL_HEADER_64 OptHdr64;
        fread(&OptHdr64, sizeof(OPTIONAL_HEADER_64), 1, program);
        ImportRVA=OptHdr64.ImportRVA;
        printf("Entry Point RVA:  0x%X\n", OptHdr64.EntryPoint);
        printf("Import Table RVA: 0x%X\n", ImportRVA);
        if (OptHdr64.SecurityRAW != 0) {
            printf("Digital Signature: SIGNED (Offset: 0x%X)\n", OptHdr64.SecurityRAW);
        } else {
            puts("Digital Signature: NOT SIGNED\n");
        }
    }
    else if(ArchMagic==0x10B){
        puts("\t=== FILE IS 32-BIT ===");
        fseek(program, -2, SEEK_CUR); 
        OPTIONAL_HEADER_32 OptHdr32;
        fread(&OptHdr32, sizeof(OPTIONAL_HEADER_32), 1, program);
        ImportRVA=OptHdr32.ImportRVA;
        printf("Entry Point RVA:  0x%X\n", OptHdr32.EntryPoint);
        printf("Import Table RVA: 0x%X\n", ImportRVA);
        if (OptHdr32.SecurityRAW != 0) {
            printf("Digital Signature: SIGNED (Offset: 0x%X)\n", OptHdr32.SecurityRAW);
        } else {
            puts("Digital Signature: NOT SIGNED\n");
        }

    }
    SECTION_HEADER section[96];
    us TotalSection=FileHdr.SectionCount;
    if(TotalSection>96){
        TotalSection=96;
    }
    fread(section,sizeof(SECTION_HEADER),TotalSection,program);
    printf("\t=== SECTION LIST (%d) ===\n",TotalSection);
    for(us sectionNow=0;sectionNow<TotalSection;sectionNow++){
    printf("Section %d: %.8s | RVA: 0x%X | RAW: 0x%X\n", 
            sectionNow + 1, 
            section[sectionNow].name, 
            section[sectionNow].VirtualAddress, 
            section[sectionNow].PointerToRawData);
    }
    ui ImportRAW=RVAtoRAW(ImportRVA,section,TotalSection);
    if (ImportRAW==0){
        puts("Invalid RVA!");
        fclose(program);
        return -1;
    }
    printf("\t=== IMPORT TABLE (0x%X) ===\n",ImportRAW);
    fseek(program,ImportRAW,SEEK_SET);
    IMPORT_TABLE dll_list[128];
    us dll_count=0;
    while(1){
        fread(&dll_list[dll_count],sizeof(IMPORT_TABLE),1,program);
        if(dll_list[dll_count].Name==0){
            break;
        }
        dll_count++;
    }
    printf("Count .dll files: %d\n",dll_count);
    uc dll_name[128];
   
    for(us i=0;i<dll_count;i++){
        ui nameRAW=RVAtoRAW(dll_list[i].Name,section,TotalSection);
        ui OrigFirstRAW=RVAtoRAW(dll_list[i].OriginalFirstThunk,section,TotalSection);
        ui FirstTnkRAW=RVAtoRAW(dll_list[i].FirstThunk,section,TotalSection);
        fseek(program,nameRAW,SEEK_SET);
        us index=0;
        while(1){
            fread(&dll_name[index],sizeof(uc),1,program);
            if (dll_name[index]=='\0'){
                break;
            }
            index++;
        }
        printf("dll name: %s\n",dll_name);
        
        ui ThunkRAW=0;
        if(OrigFirstRAW!=0){
            ThunkRAW=OrigFirstRAW;
        }
        else{
            ThunkRAW=FirstTnkRAW;
        }
        if(ThunkRAW==0){
            printf("Function not found for this dll!\n");
            continue;
        }
        fseek(program,ThunkRAW,SEEK_SET);
        while(1){
            u64 thunk_data=0;
            u64 mask=0;
            if(is64){
                fread(&thunk_data,sizeof(u64),1,program);
                mask=0x8000000000000000ULL;
            }
            else{ 
                ui thunk_data32=0;
                fread(&thunk_data32,sizeof(ui),1,program);
                thunk_data=thunk_data32;
                mask=0x80000000;
            }
            if(!thunk_data){
                break;
            }
            if(thunk_data&mask){
                unsigned short ordinal_number = thunk_data & 0xFFFF; 
                printf("\t[Ordinal] %d\n", ordinal_number);
            }
            else{
                long position_thunk=ftell(program);
                ui FuncNameRAW=RVAtoRAW((ui)thunk_data, section, TotalSection);
                fseek(program,FuncNameRAW+2,SEEK_SET);
                uc func_name[256]={0};
                us func_name_index=0;
                while(1){
                    fread(&func_name[func_name_index],sizeof(uc),1,program);
                    if(func_name[func_name_index]=='\0'){
                        break;
                    }
                    func_name_index++;
                }
                printf("\t %s\n",func_name);
                fseek(program, position_thunk, SEEK_SET);
            }
        }

    }    
}
ui main(){
    wchar_t path[261];
    printf("Path: ");
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
