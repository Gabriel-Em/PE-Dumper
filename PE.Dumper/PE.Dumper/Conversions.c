#include "Conversions.h"

PVOID p_RVA2FA(PVOID lpFileBase, DWORD RVA)
{	// Receives the file base and RVA and returns the actual memory address of the given RVA parameter.

	if (RVA == 0 || lpFileBase == 0)
		return NULL;

	PIMAGE_DOS_HEADER _image_dos_header = (PIMAGE_DOS_HEADER)lpFileBase;
	PIMAGE_NT_HEADERS32 _image_nt_headers = (PIMAGE_NT_HEADERS32)((unsigned char*)_image_dos_header + (long)_image_dos_header->e_lfanew);
	PIMAGE_SECTION_HEADER _image_section_header = (PIMAGE_SECTION_HEADER)((PTBYTE)_image_nt_headers + sizeof(_image_nt_headers->Signature) + sizeof(IMAGE_FILE_HEADER) + _image_nt_headers->FileHeader.SizeOfOptionalHeader);

	int iterations = _image_nt_headers->FileHeader.NumberOfSections;
	while (iterations > 0)
	{
		if (RVA >= _image_section_header->VirtualAddress && RVA < (_image_section_header->VirtualAddress + _image_section_header->Misc.VirtualSize))
		{
			break;
		}
		_image_section_header = _image_section_header + 1;
		iterations = iterations - 1;
	}
	if (iterations == 0)
		return NULL;
	return (PVOID)((PBYTE)lpFileBase + _image_section_header->PointerToRawData + (RVA - _image_section_header->VirtualAddress));
}