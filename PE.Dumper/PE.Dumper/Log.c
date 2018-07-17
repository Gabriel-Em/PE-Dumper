#include "Log.h"

int initLogPath()
{
	BOOL code;

	GetCurrentDirectory(MAX_PATH, logPath);
	code = CreateDirectory(LOGDIRECTORYNAME, NULL);
	if (code == ERROR_PATH_NOT_FOUND)
		return 0;

	strcat_s(logPath, MAX_PATH, "\\");
	strcat_s(logPath, MAX_PATH, LOGDIRECTORYNAME);

	return 1;
}

void log_IMAGE_DOS_HEADER(IMAGE_DOS_HEADER *img, HANDLE logHandle)
{
	DWORD	bytesWritten;
	char	buffer[BUFF_SIZE];

	sprintf_s(buffer, BUFF_SIZE, "%s\r\n%s\r\n%s\r\n\r\n",
		"============================================================================================",
		"                                    _IMAGE_DOS_HEADER",
		"============================================================================================");
	WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);

	sprintf_s(buffer, BUFF_SIZE, "Magic number:                                                   %#X (%s)\r\nBytes on last page of file:                                     %d\r\nPages in file:                                                  %d\r\nRelocations:                                                    %d\r\n...\r\nOffset to _IMAGE_NT_HEADERS                                     %#010lX\r\n\r\n",
		img->e_magic, img->e_magic == 0x5a4d ? "MZ" : "-",
		img->e_cblp,
		img->e_cp,
		img->e_crlc,
		img->e_lfanew);
	WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);
}

void log_IMAGE_NT_HEADERS(IMAGE_NT_HEADERS32 *img, HANDLE logHandle)
{
	DWORD	bytesWritten;
	char	buffer[BUFF_SIZE];

	sprintf_s(buffer, BUFF_SIZE, "%s\r\n%s\r\n%s\r\n\r\n",
		"============================================================================================",
		"                                    _IMAGE_NT_HEADERS",
		"============================================================================================");
	WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);

	sprintf_s(buffer, BUFF_SIZE,"Signature:                                                      %c%c\r\n\r\n",
		((unsigned char*)(&(img->Signature)))[0], ((unsigned char*)(&(img->Signature)))[1]);
	WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);
}

void log_IMAGE_FILE_HEADER(IMAGE_FILE_HEADER *img, HANDLE logHandle)
{
	DWORD	bytesWritten;
	char	buffer[BUFF_SIZE];

	sprintf_s(buffer, BUFF_SIZE, "%s\r\n%s\r\n%s\r\n\r\n",
		"============================================================================================",
		"                                    _IMAGE_FILE_HEADER",
		"============================================================================================");
	WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);

	sprintf_s(buffer, BUFF_SIZE, "Machine:                                                        ");
	WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);

	switch (img->Machine)
	{
	case IMAGE_FILE_MACHINE_I386:
		sprintf_s(buffer, BUFF_SIZE, "x86");
		break;
	case IMAGE_FILE_MACHINE_IA64:
		sprintf_s(buffer, BUFF_SIZE, "Intel Itanium");
		break;
	case IMAGE_FILE_MACHINE_AMD64:
		sprintf_s(buffer, BUFF_SIZE, "x64");
		break;
	default:
		sprintf_s(buffer, BUFF_SIZE, "UNKNOWN");
		break;
	}
	WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);

	time_t TimeX = (time_t)img->TimeDateStamp;
	struct tm pGMT;
	gmtime_s(&pGMT, &TimeX);
	char pTime[50];
	asctime_s(pTime, sizeof(pTime), &pGMT);

	sprintf_s(buffer, BUFF_SIZE, "\r\nNumber of sections:                                             %d\r\nTime Date Stamp:                                                %s\r\nSize optional header:                                           %d\r\n\r\n",
		img->NumberOfSections,
		pTime,
		img->SizeOfOptionalHeader);
	WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);
}

void log_IMAGE_OPTIONAL_HEADER(IMAGE_OPTIONAL_HEADER32 *img, HANDLE logHandle)
{
	DWORD	bytesWritten;
	char	buffer[BUFF_SIZE];

	sprintf_s(buffer, BUFF_SIZE, "%s\r\n%s\r\n%s\r\n\r\n",
		"============================================================================================",
		"                                    _IMAGE_OPTIONAL_HEADER",
		"============================================================================================");
	WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);

	sprintf_s(buffer, BUFF_SIZE, "Magic:                                                          %#x (%s)\r\nAddress of entry point:                                         %#010lX\r\nImage base:                                                     %#010lX\r\nSections alignment in memory:                                   %d bytes\r\nNumber of directory entries:                                    %d\r\n\r\n",
		img->Magic, img->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ? "PE32" : "PE64",
		img->AddressOfEntryPoint,
		img->ImageBase,
		img->SectionAlignment,
		img->NumberOfRvaAndSizes);
	WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);
}

void log_SECTION_NUMBER_INFO(int numberOfSections, HANDLE logHandle)
{
	DWORD	writtenBytes;
	char	buffer[BUFF_SIZE];

	sprintf_s(buffer, BUFF_SIZE, "\r\n%d sections should be found\r\n\r\n", numberOfSections);
	WriteFile(logHandle, buffer, strlen(buffer), &writtenBytes, NULL);
}

void log_SECTION_HEADER_TITLE(int sectionIndex, HANDLE logHandle)
{
	DWORD	bytesWritten;
	char	buffer[BUFF_SIZE];

	sprintf_s(buffer, BUFF_SIZE, "%s\r\n%s",
		"============================================================================================",
		"                          _IMAGE_SECTION_HEADER [section index:");
	WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);

	sprintf_s(buffer, BUFF_SIZE, " %d%s\r\n\r\n",
		sectionIndex,
		"]\r\n============================================================================================");
	WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);
}

void log_IMAGE_SECTION_HEADER(IMAGE_SECTION_HEADER *img, BYTE code, DWORD imageBase, HANDLE logHandle)
{
	DWORD	bytesWritten;
	char	buffer[BUFF_SIZE];

	sprintf_s(buffer, BUFF_SIZE, "Section name:                                                   %s\r\nPhysical Address:                                               %#010lX\r\nSection size in memory:                                         %lu bytes\r\nVirtual Address:                                                %#010lX (RVA), %#010lX (VA)\r\nSize of initialized data on disk:                               %lu bytes\r\nPointer to raw data:                                            %#010lX (RVA), %#010lX (VA)\r\n\r\n",
		!code ? (char*)(img->Name) : "Invalid Name",
		img->Misc.PhysicalAddress,
		img->Misc.VirtualSize,
		img->VirtualAddress, imageBase + img->VirtualAddress,
		img->SizeOfRawData,
		img->PointerToRawData, imageBase + img->PointerToRawData);
	WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);
}

void log_IMAGE_EXPORT_DIRECTORY_FUNCTIONS(PVOID fileBase, IMAGE_EXPORT_DIRECTORY *img, int fileSize, IMAGE_DATA_DIRECTORY *img_entry, HANDLE logHandle)
{
	DWORD	bytesWritten;
	char	buffer[BUFF_SIZE];

	sprintf_s(buffer, BUFF_SIZE, "%s\r\n%s\r\n%s\r\n\r\n",
		"--------------------------------------------------------------------------------------------",
		"                                           Functions",
		"--------------------------------------------------------------------------------------------");
	WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);

	PVOID	address;
	BYTE	code;

	address = p_RVA2FA(fileBase, img->AddressOfFunctions);
	code = _check_valid_FA(fileBase, fileSize, address);
	if (code == INVALID_FA)
	{
		sprintf_s(buffer, BUFF_SIZE, "\r\n[AddressOfFunctions]\r\n");
		WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);
		logError(code, logHandle);
		return;
	}
	PDWORD	addressOfFunctions = (PDWORD)address;

	address = p_RVA2FA(fileBase, img->AddressOfNameOrdinals);
	code = _check_valid_FA(fileBase, fileSize, address);
	if (code == INVALID_FA)
	{
		sprintf_s(buffer, BUFF_SIZE, "\r\n[AddressOfNameOrdinals]\r\n");
		WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);
		logError(code, logHandle);
		return;
	}
	PWORD	addressOfNameOrdinals = (PWORD)address;

	address = p_RVA2FA(fileBase, img->AddressOfNames);
	code = _check_valid_FA(fileBase, fileSize, address);
	if (code == INVALID_FA)
	{
		sprintf_s(buffer, BUFF_SIZE, "\r\n[AddressOfNames]\r\n");
		WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);
		logError(code, logHandle);
		return;
	}
	PDWORD	addressOfNames = (PDWORD)address;
	
	for (DWORD i = 0; i < img->NumberOfNames; i++)
	{
		address = (char*)p_RVA2FA(fileBase, addressOfNames[i]);
		code = _check_valid_FA(fileBase, fileSize, address);
		if (code == INVALID_FA)
		{
			sprintf_s(buffer, BUFF_SIZE, "\r\n[Function Name]\r\n");
			WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);
			logError(code, logHandle);
			address = NULL;
		}

		sprintf_s(buffer, BUFF_SIZE, "Name:                                                           %s\r\nOrdinal:                                                        %d\r\nAddress:                                                        %#010lX\r\n",
			address ? (char*)address : "Unknown",
			addressOfNameOrdinals[i] + img->Base,
			addressOfFunctions[addressOfNameOrdinals[i]]);
		WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);

		if (addressOfFunctions[addressOfNameOrdinals[i]] >= img_entry->VirtualAddress &&
			addressOfFunctions[addressOfNameOrdinals[i]] <= img_entry->VirtualAddress + img_entry->Size)
		{
			address = p_RVA2FA(fileBase, addressOfFunctions[addressOfNameOrdinals[i]]);
			code = _check_valid_FA(fileBase, fileSize, address);
			if (code == INVALID_FA)
			{
				sprintf_s(buffer, BUFF_SIZE, "\r\n[Forwarded function]\r\n");
				WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);
				logError(code, logHandle);
				address = NULL;
			}
			sprintf_s(buffer, BUFF_SIZE, "Forwarded to:                                                   %#010lX\r\n",
				(ULONG)address);
			WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);
		}
		WriteFile(logHandle, "\r\n", 2, &bytesWritten, NULL);

		if (fileSize - ((unsigned char*)(addressOfNames + i) - (unsigned char*)fileBase) < sizeof(DWORD) ||
			fileSize - ((unsigned char*)(addressOfNameOrdinals + i) - (unsigned char*)fileBase) < sizeof(WORD) ||
			fileSize - ((unsigned char*)(addressOfFunctions + addressOfNameOrdinals[i]) - (unsigned char*)fileBase) < sizeof(DWORD))
		{
			sprintf_s(buffer, BUFF_SIZE, "\r\nExport array function leads to memory outside current file.\r\n");
			WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);
			break;
		}
	}
}

void log_IMAGE_EXPORT_DIRECTORY(PVOID fileBase, IMAGE_EXPORT_DIRECTORY *img, int fileSize, IMAGE_DATA_DIRECTORY *img_entry, HANDLE logHandle)
{
	DWORD	bytesWritten;
	char	buffer[BUFF_SIZE];
	PVOID	address;
	BYTE	code;

	address = p_RVA2FA(fileBase, img->Name);
	code = _check_valid_FA(fileBase, fileSize, address);
	if (code == INVALID_FA)
	{
		logError(code, logHandle);
	}

	time_t TimeX = (time_t)img->TimeDateStamp;
	struct	tm pGMT;
	gmtime_s(&pGMT, &TimeX);
	char	pTime[50];
	asctime_s(pTime, sizeof(pTime), &pGMT);

	sprintf_s(buffer, BUFF_SIZE, "DLL Name:                                                       %s\r\nOrdinal Base:                                                   %d\r\nNumber of functions:                                            %d\r\nNumber of names:                                                %d\r\nTime Stamp:                                                     %s\r\n\r\n",
		code ? "Invalid DLL Name" : (char*)address,
		img->Base,
		img->NumberOfFunctions,
		img->NumberOfNames,
		pTime);
	WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);

	log_IMAGE_EXPORT_DIRECTORY_FUNCTIONS(fileBase, img, fileSize, img_entry, logHandle);
}

void log_IMAGE_EXPORT_DIRECTORY_TITLE(HANDLE logHandle)
{
	DWORD	bytesWritten;
	char	buffer[BUFF_SIZE];

	sprintf_s(buffer, BUFF_SIZE, "%s\r\n%s\r\n%s\r\n\r\n",
		"============================================================================================",
		"                                    _IMAGE_EXPORT_DIRECTORY",
		"============================================================================================");
	WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);
}

void log_IMAGE_IMPORT_DESCRIPTOR(PVOID fileBase, IMAGE_IMPORT_DESCRIPTOR *img, int fileSize, HANDLE logHandle)
{
	DWORD	bytesWritten;
	char	buffer[BUFF_SIZE];
	PVOID	address;
	BYTE	code;

	while (img->Name)
	{
		sprintf_s(buffer, BUFF_SIZE, "%s\r\n%s\r\n%s\r\n\r\n",
			"============================================================================================",
			"                                    _IMAGE_IMPORT_DESCRIPTOR",
			"============================================================================================");
		WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);

		address = p_RVA2FA(fileBase, img->Name);
		code = _check_valid_FA(fileBase, fileSize, address);
		if (code == INVALID_FA)
		{
			logError(code, logHandle);
		}

		sprintf_s(buffer, BUFF_SIZE, "DLL Name:                                                       %s\r\nFirst Thunk:                                                    %#010lX\r\nOriginal First Thunk:                                           %#010lX\r\n\r\n",
			code ? "Invalid DLL Name" : (char*)address,
			img->FirstThunk,
			img->OriginalFirstThunk);
		WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);

		IMAGE_THUNK_DATA32 *_image_thunk_data;

		if (img->OriginalFirstThunk)
		{
			address = p_RVA2FA(fileBase, img->OriginalFirstThunk);
			code = _check_valid_FA(fileBase, fileSize, address);
			if (code == INVALID_FA)
			{
				sprintf_s(buffer, BUFF_SIZE, "\r\n[OriginalFirstThunk's FA]\r\n");
				WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);
				logError(code, logHandle);
				return;
			}

			code = _check_IMAGE_THUNK_DATA_might_exist(fileBase, address, fileSize);
			if (code == IMAGE_THUNK_DATA_CANNOT_FIT)
			{
				sprintf_s(buffer, BUFF_SIZE, "\r\n[OriginalFirstThunk]\r\n");
				WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);
				logError(code, logHandle);
				return;
			}
			_image_thunk_data = (IMAGE_THUNK_DATA32*)address;
		}
		else
		{
			address = p_RVA2FA(fileBase, img->FirstThunk);
			code = _check_valid_FA(fileBase, fileSize, address);
			if (code == INVALID_FA)
			{
				sprintf_s(buffer, BUFF_SIZE, "\r\n[FirstThunk's FA]\r\n");
				WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);
				logError(code, logHandle);
				return;
			}

			code = _check_IMAGE_THUNK_DATA_might_exist(fileBase, address, fileSize);
			if (code == IMAGE_THUNK_DATA_CANNOT_FIT)
			{
				sprintf_s(buffer, BUFF_SIZE, "\r\n[FirstThunk]\r\n");
				WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);
				logError(code, logHandle);
				return;
			}
			_image_thunk_data = (IMAGE_THUNK_DATA32*)address;
		}

		sprintf_s(buffer, BUFF_SIZE, "%s\r\n%s\r\n%s\r\n\r\n",
			"--------------------------------------------------------------------------------------------",
			"                                              Functions",
			"--------------------------------------------------------------------------------------------");
		WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);

		while (_image_thunk_data->u1.AddressOfData)
		{
			if (IMAGE_SNAP_BY_ORDINAL32(_image_thunk_data->u1.Ordinal))
			{
				sprintf_s(buffer, BUFF_SIZE, "Ordinal:                                                        %d\r\n",
					IMAGE_ORDINAL32(_image_thunk_data->u1.Ordinal));
				WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);
			}
			else
			{
				address = p_RVA2FA(fileBase, _image_thunk_data->u1.AddressOfData);
				code = _check_valid_FA(fileBase, fileSize, address);

				if (code == INVALID_FA)
				{
					sprintf_s(buffer, BUFF_SIZE, "\r\n[Function Name]\r\n");
					WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);
					logError(code, logHandle);
				}

				IMAGE_IMPORT_BY_NAME *_image_import_by_name;
				
				if (!code)
					_image_import_by_name = (IMAGE_IMPORT_BY_NAME*)address;
				else
					_image_import_by_name = NULL;

				sprintf_s(buffer, BUFF_SIZE, "Function Name:                                                  %s\r\n",
					!code ? _image_import_by_name->Name : "Invalid Function Name");
				WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);
			}

			address = (PVOID)(_image_thunk_data + 1);
			code = _check_valid_FA(fileBase, fileSize, address);
			if (code == INVALID_FA)
			{
				logError(code, logHandle);
				return;
			}

			code = _check_IMAGE_THUNK_DATA_might_exist(fileBase, address, fileSize);
			if (code == IMAGE_THUNK_DATA_CANNOT_FIT)
			{
				logError(code, logHandle);
				return;
			}
			_image_thunk_data++;
		}

		WriteFile(logHandle, "\r\n", 2, &bytesWritten, NULL);

		address = (PVOID)(img + 1);
		code = _check_valid_FA(fileBase, fileSize, address);
		if (code == INVALID_FA)
		{
			logError(code, logHandle);
			return;
		}

		code = _check_IMAGE_IMPORT_DESCRIPTOR_might_exist(fileBase, address, fileSize);
		if (code == IMAGE_IMPORT_DESCRIPTOR_CANNOT_FIT)
		{
			logError(code, logHandle);
			return;
		}
		img++;
	}
}

void log_IMPORTS_GENERAL_TITLE(HANDLE logHandle)
{
	DWORD	bytesWritten;
	char	buffer[BUFF_SIZE];

	sprintf_s(buffer, BUFF_SIZE, "%s\r\n%s\r\n%s\r\n\r\n",
		"============================================================================================",
		"                                             IMPORTS",
		"============================================================================================");
	WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);
}

void log_CUSTOM_MESSAGE(char *buffer, HANDLE logHandle)
{
	DWORD	bytesWritten;

	WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);
}