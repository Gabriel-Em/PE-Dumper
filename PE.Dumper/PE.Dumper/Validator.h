#pragma once

#include <Windows.h>
#include "Conversions.h"
#include "PE_Status.h"

#define VALIDATIONSUCCESSFUL	0

BYTE							_check_IMAGE_DOS_HEADER_might_exist(int fileSize);
BYTE							_check_IMAGE_DOS_HADER_e_magic(IMAGE_DOS_HEADER *img);
BYTE							_check_IMAGE_DOS_HEADER_e_lfanew(IMAGE_DOS_HEADER *img, int fileSize);
BYTE							_check_IMAGE_NT_HEADERS_might_exist(int fileSize, long e_lfanew);
BYTE							_check_IMAGE_NT_HEADERS_Signature(IMAGE_NT_HEADERS32 *img);
BYTE							_check_File_is_32bit(IMAGE_NT_HEADERS32 *img);
BYTE							_check_IMAGE_SECTION_HEADER_S_might_exist(PVOID fileBase, PVOID pointerToFirstSection, int numberOfSections, int fileSize);
BYTE							_check_IMAGE_SECTION_HEADER_name(IMAGE_SECTION_HEADER *img);
BYTE							_check_valid_FA(PVOID fileBase, int fileSize, PVOID VirtualAddress);
BYTE							_check_IMAGE_EXPORT_DIRECTORY_might_exist(PVOID fileBase, PVOID pointerToImageExportDirectory, int fileSize);
BYTE							_check_IMAGE_OPTIONAL_HEADER_might_exist(PVOID fileBase, PVOID pointerToImageOptionalHeader, int fileSize, WORD sizeofImageOptionalHeader);
BYTE							_check_IMAGE_IMPORT_DESCRIPTOR_might_exist(PVOID fileBase, PVOID pointerToImageImportDescriptor, int fileSize);
BYTE							_check_IMAGE_THUNK_DATA_might_exist(PVOID fileBase, PVOID pointerToThunkData, int fileSize);