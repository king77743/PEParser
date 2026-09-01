#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "pe_structures.h"
#include "log.h"
ui parser(wchar_t * path,wchar_t* PathToSave){
    uc is64=0;
    ui ImportRVA=0;
    ui ExportRVA=0;
    ui ExportTableStart=0;
    ui ExportTableEnd=0;
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
        LogFileHeader(pathtosave,FileHdr);
        OPTIONAL_HEADER_64 * OptHdr64=(OPTIONAL_HEADER_64*)PtrToOptional;
        ImportRVA=OptHdr64->ImportRVA;
        ExportRVA=OptHdr64->ExportRVA;
        ExportTableStart=OptHdr64->ExportRVA;
        ExportTableEnd=OptHdr64->ExportSize;
        LogOptHdr64(pathtosave,OptHdr64);
        
    }
    else if(ArchMagic==0x10B){
        fputs("\t=== FILE IS 32-BIT ===\n",pathtosave);
        LogFileHeader(pathtosave,FileHdr);
        OPTIONAL_HEADER_32 * OptHdr32=(OPTIONAL_HEADER_32*)PtrToOptional;
        ImportRVA=OptHdr32->ImportRVA;
        ExportRVA=OptHdr32->ExportRVA;
        ExportTableStart=OptHdr32->ExportRVA;
        ExportTableEnd=OptHdr32->ExportSize;
        LogOptHdr32(pathtosave,OptHdr32);
    }
  
    ui buffer_size = (SectionCount * 64) + 251;
    uc* section_buffer_size = (uc*)malloc(buffer_size);
    if (section_buffer_size==NULL){
        puts("Memory allocattion for Section Table!");
        fclose(pathtosave);
        free(file_buffer);
        return -1;
    }
    SECTION_HEADER * SectionTable=(SECTION_HEADER*)(PtrToOptional+FileHdr->SizeOfOptinalHeader);
    if (SectionTableParser(pathtosave, SectionTable, SectionCount, (char*)section_buffer_size, buffer_size) != 0) {
        puts("Sections are confused!");
        fclose(pathtosave);
        free(file_buffer);
        free(section_buffer_size);
        return -1;
    }

    if(ExportRVA!=0){
        ui ExportTblRAW=RVAtoRAW(ExportRVA,SectionTable,SectionCount);
        if (ExportTblRAW!=0){
            EXPORT_TABLE* ExportTbl=(EXPORT_TABLE*)(file_buffer+ExportTblRAW);
            ExportTableParser(file_buffer,pathtosave,ExportTbl,SectionTable,SectionCount,ExportTableStart,ExportTableEnd);
        }
        else{
            puts("Export Table RAW return 0");
        }
    }  
    if (ImportRVA==0){
        puts("This program does not have an Import Directory. But ntdll.dll and kernel32.dll are present");
        fclose(pathtosave);
        free(file_buffer);
        free(section_buffer_size);
        return 1;
    }
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
            continue;
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
        ImportTbl++;

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
            path[i] = L'\0';
            break; 
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
