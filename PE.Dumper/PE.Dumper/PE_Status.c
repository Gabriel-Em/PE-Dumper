#include "PE_Status.h"

void logError(BYTE code, HANDLE logHandle)
{
	DWORD	bytesWritten;
	char	buffer[BUFF_SIZE];

	switch (code)
	{
	case IMAGE_DOS_HEADER_CANNOT_FIT:
		sprintf_s(buffer, BUFF_SIZE, "File size isn't big enough to fit an _IMAGE_DOS_HEADER.");
		break;
	case IMAGE_DOS_HEADER_INVALID_MAGIC:
		sprintf_s(buffer, BUFF_SIZE, "Magic for _IMAGE_DOS_HEADER was invalid.");
		break;
	case IMAGE_DOS_HEADER_INVALID_ELFANEW:
		sprintf_s(buffer, BUFF_SIZE, "E_lfanew for _IMAGE_DOS_HEADER was invalid.");
		break;
	case IMAGE_NT_HEADERS_CANNOT_FIT:
		sprintf_s(buffer, BUFF_SIZE, "File size isn't big enough to fit an _IMAGE_NT_HEADERS.");
		break;
	case IMAGE_NT_HEADERS_INVALID_SIGNATURE:
		sprintf_s(buffer, BUFF_SIZE, "Signature for _IMAGE_NT_HEADERS was invalid.");
		break;
	case FILE_NOT_32BIT:
		sprintf_s(buffer, BUFF_SIZE, "File structure isn't 32bit.");
		break;
	case IMAGE_SECTION_HEADER_S_CANNOT_FIT:
		sprintf_s(buffer, BUFF_SIZE, "File size isn't big enough to fit every _IMAGE_SECTION_HEADER relative to the number of sections found in _IMAGE_OPTIONAL_HEADER.");
		break;
	case IMAGE_SECTION_HEADER_INVALID_NAME:
		sprintf_s(buffer, BUFF_SIZE, "Invalid section name.");
		break;
	case INVALID_FA:
		sprintf_s(buffer, BUFF_SIZE, "Invalid FA.");
		break;
	case IMAGE_EXPORT_DIRECTORY_CANNOT_FIT:
		sprintf_s(buffer, BUFF_SIZE, "File size isn't big enough to fit an _IMAGE_EXPORT_DIRECTORY starting at its relative file address.");
		break;
	case IMAGE_OPTIONAL_HEADER_CANNOT_FIT:
		sprintf_s(buffer, BUFF_SIZE, "File size isn't big enough to fit an _IMAGE_OPTIONAL_HEADER.");
	case IMAGE_IMPORT_DESCRIPTOR_CANNOT_FIT:
		sprintf_s(buffer, BUFF_SIZE, "File size isn't big enough to fit the next _IMAGE_IMPORT_DESCRIPTOR starting at its relative file address.");
		break;
	case IMAGE_THUNK_DATA_CANNOT_FIT:
		sprintf_s(buffer, BUFF_SIZE, "File size isn't big enough to fit the next _IMAGE_THUNK_DATA starting at its relative file address.");
		break;
	default:
		break;
	}
	WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);
	sprintf_s(buffer, BUFF_SIZE, " [Error code %d]\r\n", code);
	WriteFile(logHandle, buffer, strlen(buffer), &bytesWritten, NULL);
}