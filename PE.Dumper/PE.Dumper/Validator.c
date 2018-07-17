#pragma once

#include "Validator.h"

BYTE _check_IMAGE_DOS_HEADER_might_exist(int fileSize)
{
	if (fileSize < sizeof(IMAGE_DOS_HEADER))
		return IMAGE_DOS_HEADER_CANNOT_FIT;
	return VALIDATIONSUCCESSFUL;
}

BYTE _check_IMAGE_DOS_HADER_e_magic(IMAGE_DOS_HEADER *img)
{
	if (((unsigned char*)(&(img->e_magic)))[0] != 'M' || ((unsigned char*)(&(img->e_magic)))[1] != 'Z')
		return IMAGE_DOS_HEADER_INVALID_MAGIC;
	return VALIDATIONSUCCESSFUL;
}

BYTE _check_IMAGE_DOS_HEADER_e_lfanew(IMAGE_DOS_HEADER *img, int fileSize)
{
	if ((ULONG)img->e_lfanew > (ULONG)fileSize)
		return IMAGE_DOS_HEADER_INVALID_ELFANEW;
	return VALIDATIONSUCCESSFUL;
}

BYTE _check_IMAGE_NT_HEADERS_might_exist(int fileSize, long e_lfanew)
{
	if (fileSize - e_lfanew < sizeof(IMAGE_NT_HEADERS32))
		return IMAGE_NT_HEADERS_CANNOT_FIT;
	return VALIDATIONSUCCESSFUL;
}

BYTE _check_IMAGE_NT_HEADERS_Signature(IMAGE_NT_HEADERS32 *img)
{
	if (((unsigned char*)(&(img->Signature)))[0] == 'P' &&
		((unsigned char*)(&(img->Signature)))[1] == 'E' &&
		((unsigned char*)(&(img->Signature)))[2] == 0 &&
		((unsigned char*)(&(img->Signature)))[3] == 0)
		return VALIDATIONSUCCESSFUL;
	return IMAGE_NT_HEADERS_INVALID_SIGNATURE;
}

BYTE _check_File_is_32bit(IMAGE_NT_HEADERS32 *img)
{
	if (img->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 &&
		img->FileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE &&
		img->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		return VALIDATIONSUCCESSFUL;
	return FILE_NOT_32BIT;
}

BYTE _check_IMAGE_SECTION_HEADER_S_might_exist(PVOID fileBase, PVOID pointerToFirstSection, int numberOfSections, int fileSize)
{
	fileSize = fileSize - ((unsigned char*)pointerToFirstSection - (unsigned char*)fileBase);

	if ((unsigned int)fileSize < (unsigned int)numberOfSections * sizeof(IMAGE_SECTION_HEADER))
		return IMAGE_SECTION_HEADER_S_CANNOT_FIT;
	return VALIDATIONSUCCESSFUL;
}

BYTE _check_IMAGE_SECTION_HEADER_name(IMAGE_SECTION_HEADER *img)
{
	for (int i = 0; i < IMAGE_SIZEOF_SHORT_NAME; i++)
		if (!img->Name[i])
			return VALIDATIONSUCCESSFUL;
	return IMAGE_SECTION_HEADER_INVALID_NAME;
}

BYTE _check_valid_FA(PVOID fileBase, int fileSize, PVOID FileAddress)
{
	if (FileAddress == NULL || (unsigned char*)fileBase + fileSize < (unsigned char*)FileAddress)
		return INVALID_FA;
	return VALIDATIONSUCCESSFUL;
}

BYTE _check_IMAGE_EXPORT_DIRECTORY_might_exist(PVOID fileBase, PVOID pointerToImageExportDirectory, int fileSize)
{
	fileSize = fileSize - ((unsigned char*)pointerToImageExportDirectory - (unsigned char*)fileBase);
	if (fileSize < sizeof(IMAGE_EXPORT_DIRECTORY))
		return IMAGE_EXPORT_DIRECTORY_CANNOT_FIT;
	return VALIDATIONSUCCESSFUL;
}

BYTE _check_IMAGE_OPTIONAL_HEADER_might_exist(PVOID fileBase, PVOID pointerToImageOptionalHeader, int fileSize, WORD sizeofImageOptionalHeader)
{
	fileSize = fileSize - ((unsigned char*)pointerToImageOptionalHeader - (unsigned char *)fileBase);
	if (fileSize < (int)sizeofImageOptionalHeader)
		return IMAGE_OPTIONAL_HEADER_CANNOT_FIT;
	return VALIDATIONSUCCESSFUL;
}

BYTE _check_IMAGE_IMPORT_DESCRIPTOR_might_exist(PVOID fileBase, PVOID pointerToImageImportDescriptor, int fileSize)
{
	fileSize = fileSize - ((unsigned char*)pointerToImageImportDescriptor - (unsigned char*)fileBase);
	if (fileSize < sizeof(IMAGE_EXPORT_DIRECTORY))
		return IMAGE_IMPORT_DESCRIPTOR_CANNOT_FIT;
	return VALIDATIONSUCCESSFUL;
}

BYTE _check_IMAGE_THUNK_DATA_might_exist(PVOID fileBase, PVOID pointerToThunkData, int fileSize)
{
	fileSize = fileSize - ((unsigned char*)pointerToThunkData - (unsigned char*)fileBase);
	if (fileSize < sizeof(IMAGE_THUNK_DATA32))
		return IMAGE_THUNK_DATA_CANNOT_FIT;
	return VALIDATIONSUCCESSFUL;
}