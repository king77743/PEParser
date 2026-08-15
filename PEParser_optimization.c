#include <stdio.h>
#include <stdlib.h>
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

void HEX(void * value,unsigned char bytes,unsigned char* hex_buffer){
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
ui parser(wchar_t * path,wchar_t* PathToSave){
    uc is64=0;
    ui ImportRVA=0;
    char OutBuffer[20];
    FILE *program=_wfopen(path,L"rb");
    if (program==NULL){
        puts("Program don't open!");
        return -1;
    }
    FILE *pathtosave=_wfopen(PathToSave,L"w");
    if (pathtosave==NULL){
        puts("Log file don't open!");
        return -1;
    }
    _fseeki64(program,0,SEEK_END);
    u64 file_size=_ftelli64(program);
    _fseeki64(program,0,SEEK_SET);
    uc* file_buffer=(uc*)malloc(file_size);
    if (file_buffer==NULL){
        puts("Memory allocation!");
        fclose(program);
        fclose(pathtosave);
        return -1;
    }
    if(fread(file_buffer,file_size,1,program)!=1){
        puts("File reading error!");
        fclose(program);
        fclose(pathtosave);
        free(file_buffer);
        return -1;
    }
    fclose(program);
    DOS_HEADER * DosHeader=(DOS_HEADER*)file_buffer;
    if (DosHeader->magic!=0x5A4D){
        puts("The signature is invalid!");
        fclose(pathtosave);
        free(file_buffer);
        return -1;
    }
    FILE_HDR * FileHdr=(FILE_HDR*)(file_buffer+DosHeader->PE_address_in_dos);
    if (FileHdr->signature!=0x00004550){
        puts("PE signature is invalid!");
        fclose(pathtosave);
        free(file_buffer);
        return -1;
    }
    us SectionCount=FileHdr->SectionCount;
    uc *PtrToOptional=file_buffer+DosHeader->PE_address_in_dos+24;
    us ArchMagic=*(us*)PtrToOptional;
    if (ArchMagic==0x20B){
        is64=1;
        fputs("\t=== FILE IS 64-BIT ===\n",pathtosave);
        OPTIONAL_HEADER_64 * OptHdr64=(OPTIONAL_HEADER_64*)PtrToOptional;
        ImportRVA=OptHdr64->ImportRVA;
        HEX(&(OptHdr64->EntryPoint),sizeof(OptHdr64->EntryPoint),OutBuffer); 
        fputs("Entry point RVA: ",pathtosave);fputs(OutBuffer,pathtosave);fputs("\n",pathtosave);
        HEX(&ImportRVA, sizeof(ImportRVA), OutBuffer);
        fputs("Import Table RVA: ", pathtosave); fputs(OutBuffer, pathtosave); fputs("\n", pathtosave);
        if (OptHdr64->SecurityRAW!=0){
            HEX(&(OptHdr64->SecurityRAW),sizeof(OptHdr64->SecurityRAW),OutBuffer);
            fputs("Digital Signature: SIGNED (Offset: ", pathtosave);fputs(OutBuffer, pathtosave); fputs(")\n", pathtosave);
        }
        else{
            fputs("Digital Signature: NOT SIGNED\n",pathtosave);
        }
    }
    else if(ArchMagic==0x10B){
        fputs("\t=== FILE IS 32-BIT ===\n",pathtosave);
        
        OPTIONAL_HEADER_32 * OptHdr32=(OPTIONAL_HEADER_32*)PtrToOptional;
        ImportRVA=OptHdr32->ImportRVA;
        HEX(&(OptHdr32->EntryPoint),sizeof(OptHdr32->EntryPoint),OutBuffer); 
        fputs("Entry point RVA: ",pathtosave);fputs(OutBuffer,pathtosave);fputs("\n",pathtosave);
        HEX(&ImportRVA, sizeof(ImportRVA), OutBuffer);
        fputs("Import Table RVA: ", pathtosave); fputs(OutBuffer, pathtosave); fputs("\n", pathtosave);
        if (OptHdr32->SecurityRAW!=0){
            HEX(&(OptHdr32->SecurityRAW),sizeof(OptHdr32->SecurityRAW),OutBuffer);
            fputs("Digital Signature: SIGNED (Offset: ", pathtosave);fputs(OutBuffer, pathtosave); fputs(")\n", pathtosave);
        }
        else{
            fputs("Digital Signature: NOT SIGNED\n",pathtosave);
        }
    }
    uc* section_buffer_size=(uc*)malloc(SectionCount*64+1);
    ui buffer_size=FileHdr->SectionCount*64+1;
    if (section_buffer_size==NULL){
        puts("Memory allocattion for Section Table!");
        fclose(pathtosave);
        free(file_buffer);
        return -1;
    }
    ui char_written=0;

    SECTION_HEADER * SectionTable=(SECTION_HEADER*)(PtrToOptional+FileHdr->SizeOfOptinalHeader);
    for (us SectionNow=0;SectionNow<FileHdr->SectionCount;SectionNow++){
        ui space=buffer_size-char_written;
        int bytes=snprintf((char*)section_buffer_size+char_written,space,"Section %d: %.8s | RVA: 0x%X | RAW: 0x%X\n", 
            SectionNow + 1, 
            SectionTable[SectionNow].name, 
            SectionTable[SectionNow].VirtualAddress, 
            SectionTable[SectionNow].PointerToRawData);
        if (bytes<0 || (ui)bytes>=space){
            puts("Sections are confused!");
            fclose(pathtosave);
            free(file_buffer);
            free(section_buffer_size);
            return -1;
        }
        char_written+=bytes;
    }
    fputs(section_buffer_size,pathtosave);
    ui ImportRAW=RVAtoRAW(ImportRVA,SectionTable,FileHdr->SectionCount);
    if(ImportRAW==0){
        puts("Invalid Import RVA!");
        fclose(pathtosave);
        free(file_buffer);
        free(section_buffer_size);
        return -1;
    }
    HEX(&ImportRAW,sizeof(ImportRAW),OutBuffer);
    fputs("Import Table RAW: ", pathtosave); fputs(OutBuffer, pathtosave); fputs("\n", pathtosave);   
    IMPORT_TABLE *ImportTbl=(IMPORT_TABLE*)(file_buffer+ImportRAW);
    IMPORT_TABLE *ScanTbl=ImportTbl;
    us DLLCount=0;
    while(ScanTbl->Name!=0){
        DLLCount++;
        ScanTbl++;
    }
    us_to_dec(DLLCount, OutBuffer); 
    fputs("DLL count: ", pathtosave);
    fputs(OutBuffer, pathtosave);
    fputs("\n", pathtosave);
    for (us DLLNow=0;DLLNow<DLLCount;DLLNow++){
        ui DLLNameRAW=RVAtoRAW(ImportTbl->Name,SectionTable,SectionCount);
        ui OriginalFirsThunkRAW=RVAtoRAW(ImportTbl->OriginalFirstThunk,SectionTable,SectionCount);
        ui FirsThunkRAW=RVAtoRAW(ImportTbl->FirstThunk,SectionTable,SectionCount);
        uc* Name=file_buffer+DLLNameRAW;
        fputs("DLL name: ",pathtosave);
        fputs((char*)Name,pathtosave);
        fputs("\n",pathtosave);
        ui ThunkRAW=0;
        if (OriginalFirsThunkRAW!=0){
            ThunkRAW=OriginalFirsThunkRAW;
        }
        else{
            ThunkRAW=FirsThunkRAW;
        }
        if (ThunkRAW==0){
            fputs("\t",pathtosave);
            fputs("Function not found for this DLL",pathtosave);
            fputs("\n",pathtosave);
        }
        uc step=is64?8:4;
        u64 mask=is64?0x8000000000000000ULL : 0x80000000U;
        uc* CurrentAddress=file_buffer+ThunkRAW;
        while(1){
            u64 value=0;
            if(is64){
                value=*(u64*)(CurrentAddress);
            }
            else{
                value=*(ui*)(CurrentAddress);
            }
            if(!value){
                break;
            }
            if (value&mask){
                us ordinal_number=value&0xFFFF;
                us_to_dec(ordinal_number,OutBuffer);
                fputs("\tOrdinal number: ", pathtosave);     
                fputs(OutBuffer,pathtosave);
                fputs("\n", pathtosave);   
                CurrentAddress+=step;
                continue;
            }
            else{
                ui FuncNameRAW=RVAtoRAW((ui)value,SectionTable,SectionCount);
                if (FuncNameRAW==0){
                    fputs("\t",pathtosave);
                    fputs("[ERROR] Invalid Function Name RVA",pathtosave);
                    fputs("\n",pathtosave);
                    
                }
                else{
                    char *FuncName=(char*)(file_buffer+FuncNameRAW+2);
                    fputs("\t",pathtosave);
                    fputs(FuncName,pathtosave);
                    fputs("\n",pathtosave);
                }
            }
            CurrentAddress+=step;


            
        }

    }
    
    free(file_buffer);
    free(section_buffer_size);
    puts("Log file is done!");
    return 1;
}
ui main(){
    wchar_t path[261];
    printf("Path: ");
    fgetws(path,261,stdin);
    int i = 0;
    while (path[i] != L'\0') {
        if (path[i] == L'\n') {
            if(path[i-1]=='e' && path[i-2]=='x' && path[i-3]=='e' && path[i-4]=='.'){
                path[i] = L'\0';
                break; 
            }
            else{
                puts("Only exe files!");
                return -1;
            }
        }
        i++;
    }
    wchar_t PathToSave[261];
    printf("Path to save result: ");
    fgetws(PathToSave,261,stdin);
    i=0;
    while(PathToSave[i]!=L'\0'){
        if (PathToSave[i]==L'\n'){
            PathToSave[i]=L'\0';
            break;
        }
        i++;
    }
    parser(path,PathToSave);
    return 0;
}