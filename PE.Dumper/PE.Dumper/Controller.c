#include "Controller.h"

BYTE analyzeSections(PVOID pointerToFirstSection, int numberOfSections, int fileSize, PVOID fileBase, DWORD imageBase, HANDLE logHandle)
{
	IMAGE_SECTION_HEADER	*sectionHeader;
	BYTE					code;

	log_SECTION_NUMBER_INFO(numberOfSections, logHandle);

	code = _check_IMAGE_SECTION_HEADER_S_might_exist(fileBase, pointerToFirstSection, numberOfSections, fileSize);
	if (code == IMAGE_SECTION_HEADER_S_CANNOT_FIT)
	{
		logError(code, logHandle);
		return code;
	}

	sectionHeader = (IMAGE_SECTION_HEADER*)pointerToFirstSection;

	for (int i = 1; i <= numberOfSections; i++)
	{
		log_SECTION_HEADER_TITLE(i, logHandle);

		code = _check_IMAGE_SECTION_HEADER_name(sectionHeader);
		if (code == IMAGE_SECTION_HEADER_INVALID_NAME)
		{
			logError(code, logHandle);
		}
		log_IMAGE_SECTION_HEADER(sectionHeader, code, imageBase, logHandle);

		sectionHeader += 1;
	}

	return 0;
}

void analyzeExports(IMAGE_DATA_DIRECTORY *img, PVOID fileBase, int fileSize, HANDLE logHandle)
{
	IMAGE_EXPORT_DIRECTORY		*_image_export_directory;
	BYTE						code;
	PVOID						address;

	log_IMAGE_EXPORT_DIRECTORY_TITLE(logHandle);

	address = p_RVA2FA(fileBase, img->VirtualAddress);
	code = _check_valid_FA(fileBase, fileSize, address);
	if (code == INVALID_FA)
	{
		logError(code, logHandle);
		return;
	}

	code = _check_IMAGE_EXPORT_DIRECTORY_might_exist(fileBase, address, fileSize);
	if (code == IMAGE_EXPORT_DIRECTORY_CANNOT_FIT)
	{
		logError(code, logHandle);
		return;
	}
	_image_export_directory = (IMAGE_EXPORT_DIRECTORY*)address;
	log_IMAGE_EXPORT_DIRECTORY(fileBase, _image_export_directory, fileSize, img, logHandle);
}

void analyzeImports(IMAGE_DATA_DIRECTORY *img, PTBYTE fileBase, int fileSize, HANDLE logHandle)
{
	IMAGE_IMPORT_DESCRIPTOR		*_image_import_descriptor;
	BYTE						code;
	PVOID						address;

	log_IMPORTS_GENERAL_TITLE(logHandle);

	address = p_RVA2FA((LPVOID)fileBase, img->VirtualAddress);
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
	_image_import_descriptor = (IMAGE_IMPORT_DESCRIPTOR*)address;
	log_IMAGE_IMPORT_DESCRIPTOR(fileBase, _image_import_descriptor, fileSize, logHandle);
}

void analyze(PTBYTE pBuf, int fileSize, HANDLE logHandle)
{
	IMAGE_DOS_HEADER			*_image_dos_header;
	IMAGE_NT_HEADERS32			*_image_nt_headers;
	IMAGE_FILE_HEADER			*_image_file_header;
	IMAGE_OPTIONAL_HEADER32		*_image_optional_header;
	BYTE						code;

	// _IMAGE_DOS_HEADER

	code = _check_IMAGE_DOS_HEADER_might_exist(fileSize);
	if (code == IMAGE_DOS_HEADER_CANNOT_FIT)
	{
		logError(code, logHandle);
		return;
	}
	_image_dos_header = (IMAGE_DOS_HEADER*)pBuf;
	
	code = _check_IMAGE_DOS_HADER_e_magic(_image_dos_header);
	if (code == IMAGE_DOS_HEADER_INVALID_MAGIC)
	{
		logError(code, logHandle);
		return;
	}

	log_IMAGE_DOS_HEADER(_image_dos_header, logHandle);

	// _IMAGE_NT_HEADERS
	
	code = _check_IMAGE_DOS_HEADER_e_lfanew(_image_dos_header, fileSize);
	if (code == IMAGE_DOS_HEADER_INVALID_ELFANEW)
	{
		logError(code, logHandle);
		return;
	}

	code = _check_IMAGE_NT_HEADERS_might_exist(fileSize, _image_dos_header->e_lfanew);
	if (code == IMAGE_NT_HEADERS_CANNOT_FIT)
	{
		logError(code, logHandle);
		return;
	}

	_image_nt_headers = (IMAGE_NT_HEADERS32*)((PTBYTE)_image_dos_header + _image_dos_header->e_lfanew);

	code =_check_IMAGE_NT_HEADERS_Signature(_image_nt_headers);
	if (code == IMAGE_NT_HEADERS_INVALID_SIGNATURE)
	{
		logError(code, logHandle);
		return;
	}
	log_IMAGE_NT_HEADERS(_image_nt_headers, logHandle);

	code = _check_File_is_32bit(_image_nt_headers);
	if (code == FILE_NOT_32BIT)
	{
		logError(code, logHandle);
		return;
	}

	// _IMAGE_FILE_HEADER

	_image_file_header = &(_image_nt_headers->FileHeader);

	log_IMAGE_FILE_HEADER(_image_file_header, logHandle);

	// _IMAGE_OPTIONAL_HEADER

	code = _check_IMAGE_OPTIONAL_HEADER_might_exist((PVOID)_image_dos_header, (PVOID)&(_image_nt_headers->OptionalHeader), fileSize, _image_file_header->SizeOfOptionalHeader);
	if (code == IMAGE_OPTIONAL_HEADER_CANNOT_FIT)
	{
		logError(code, logHandle);
		return;
	}
	_image_optional_header = &(_image_nt_headers->OptionalHeader);

	log_IMAGE_OPTIONAL_HEADER(_image_optional_header, logHandle);

	// _IMAGE_SECTION_HEADER

	if (_image_file_header->NumberOfSections)
	{
		code = analyzeSections((PTBYTE)_image_optional_header + _image_file_header->SizeOfOptionalHeader, _image_file_header->NumberOfSections, fileSize, (PVOID)_image_dos_header, _image_optional_header->ImageBase, logHandle);
		if (code == IMAGE_SECTION_HEADER_S_CANNOT_FIT)
		{
			log_CUSTOM_MESSAGE("Due to missing sections, looking up exports or imports could lead to undefined behavior. [Aborting export and import analysis]\r\n", logHandle);
			return;
		}

		// _IMAGE_DIRECTORY_ENTRY_EXPORT

		if (IMAGE_DIRECTORY_ENTRY_EXPORT >= _image_optional_header->NumberOfRvaAndSizes || _image_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0)
			log_CUSTOM_MESSAGE("Image doesn't have an export table.\r\n\r\n", logHandle);
		else
		{
			analyzeExports(&(_image_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]), (PTBYTE)_image_dos_header, fileSize, logHandle);
		}

		// _IMAGE_DIRECTORY_ENTRY_IMPORT

		if (IMAGE_DIRECTORY_ENTRY_IMPORT >= _image_optional_header->NumberOfRvaAndSizes || _image_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
			log_CUSTOM_MESSAGE("Image doesn't have an import table.\r\n\r\n", logHandle);
		else
		{
			analyzeImports(&(_image_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]), (PTBYTE)_image_dos_header, fileSize, logHandle);
		}
	}
}

void	_scan(char *path, HANDLE logHandle)
{
	HANDLE	hMapFile;
	PTBYTE	pBuf;
	TCHAR	szName[MAX_PATH];
	char	buffer[BUFF_SIZE];

	HANDLE hFile = CreateFile(path, GENERIC_READ , 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		sprintf_s(buffer, BUFF_SIZE, "Failed to open file %s. Error Code %lu.\r\n",
			path,
			GetLastError());
		log_CUSTOM_MESSAGE(buffer, logHandle);
		return;
	}

	hMapFile = CreateFileMapping(
		hFile,
		NULL,                    
		PAGE_READONLY,			 
		0,                       
		0,						 
		szName);                 


	if (hMapFile == NULL || hMapFile == INVALID_HANDLE_VALUE)
	{
		sprintf_s(buffer, BUFF_SIZE, "Could not create file mapping object for file %s. Error Code %lu.\r\n",
			path,
			GetLastError());
		log_CUSTOM_MESSAGE(buffer, logHandle);
		CloseHandle(hFile);
		return;
	}

	pBuf = (PTBYTE)MapViewOfFile(hMapFile,
		FILE_MAP_READ,
		0,
		0,
		0);

	if (pBuf == NULL)
	{
		printf("Could not map view of file %s. Error Code %lu.\r\n",
			path,
			GetLastError());
		log_CUSTOM_MESSAGE(buffer, logHandle);
		CloseHandle(hFile);
		CloseHandle(hMapFile);
		return;
	}
	analyze(pBuf, GetFileSize(hFile, NULL), logHandle);
	CloseHandle(hFile);
	CloseHandle(hMapFile);
	UnmapViewOfFile(pBuf);

	return;
}

int lookThrough(char *pattern, int recursive, char *dirPath)
{
	WIN32_FIND_DATA ffd;
	TCHAR currentPath[MAX_PATH];
	HANDLE hFind = INVALID_HANDLE_VALUE;
	int filesScanned;
	int code;
	DWORD attributes;
	char *path;

	code = SetCurrentDirectory(dirPath);
	if (code == 0)
	{
		printf("Failed to set %s as current directory. Error code %lu.\n", dirPath, GetLastError());
		return 0;
	}
	GetCurrentDirectory(MAX_PATH, currentPath);

	hFind = FindFirstFile(pattern, &ffd);

	filesScanned = 0;

	if (INVALID_HANDLE_VALUE != hFind)	// no files with pattern extension found
	{
		do
		{
			attributes = GetFileAttributes(ffd.cFileName);
			if (attributes == INVALID_FILE_ATTRIBUTES)
			{
				printf("Could not determine the file type of %s\n", ffd.cFileName);
			}
			else
			{
				if (strcmp(ffd.cFileName, ".") && strcmp(ffd.cFileName, "..") && attributes != FILE_ATTRIBUTE_DIRECTORY)
				{
					path = combinePath(currentPath, ffd.cFileName);
					if (path)
					{
						pushToList(path);
						if (!SetEvent(Events[0]))	// signal that a file path was added to the list so there's work to be done
						{
							printf("SetEvent failed (%d)\n", GetLastError());
							return filesScanned;
						}
						filesScanned++;
					}
				}
			}
		} while (FindNextFile(hFind, &ffd) != 0);
	}
	FindClose(hFind);

	if (recursive)
	{

		hFind = FindFirstFile("*", &ffd);

		if (INVALID_HANDLE_VALUE != hFind)
		{
			do
			{
				attributes = GetFileAttributes(ffd.cFileName);
				if (attributes == INVALID_FILE_ATTRIBUTES)
				{
					printf("Could not determine the file type of %s\n", ffd.cFileName);
				}
				else
				{
					if (attributes == FILE_ATTRIBUTE_DIRECTORY)
					{
						if (strcmp(ffd.cFileName, ".") && strcmp(ffd.cFileName, "..") && strcmp(ffd.cFileName, LOGDIRECTORYNAME))
						{
							filesScanned += lookThrough(pattern, recursive, ffd.cFileName);
						}
					}
				}
				SetCurrentDirectory(currentPath);
			} while (FindNextFile(hFind, &ffd) != 0);
			FindClose(hFind);
		}
	}

	return filesScanned;
}

/*
 *	Function that's executed by each thread each time work was signaled to be done
 */

int do_work()
{
	char *path, *fileName, *pathToLogFile;
	HANDLE hLogFile;

	EnterCriticalSection(&list_cs);
	if (IsListEmpty(ListHead))
	{
		LeaveCriticalSection(&list_cs);
		return ERRORDOINGWORK;
	}

	path = popFromList();
	printf("Thread id: %5d is scanning '%s'\n", GetCurrentThreadId(), path);
	LeaveCriticalSection(&list_cs);

	fileName = pathToFileName(path);				// generating log file name
	if (!fileName)
	{
		printf("\nGenerating filename from path %s failed!\n", path);
		return ERRORDOINGWORK;
	}

	pathToLogFile = combinePath(logPath, fileName);	// generating path to log file associated to scan file

	hLogFile = CreateFile(pathToLogFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hLogFile == INVALID_HANDLE_VALUE) {
		printf("Failed to create log file %s. Error Code %lu.\n", pathToLogFile, GetLastError());

		if (path)
			free(path);
		if (fileName)
			free(fileName);
		if (pathToLogFile)
			free(pathToLogFile);
		CloseHandle(hLogFile);

		return ERRORDOINGWORK;
	}

	_scan(path, hLogFile);

	if (path)
		free(path);
	if (fileName)
		free(fileName);
	if (pathToLogFile)
		free(pathToLogFile);
	CloseHandle(hLogFile);

	return WORKDONESUCCESSFULLY;
}

int init(char *pattern, int recursive, char *dirPath, int numberOfThreads)
{
	int noOfFilesScanned;

	if (!initLogPath())
	{
		printf("Initializing log directory failed!\n");
		return 0;
	}
	CreateEventsAndThreads(numberOfThreads, &do_work);
	initList();
	noOfFilesScanned = lookThrough(pattern, recursive, dirPath);

	if (!SetEvent(Events[1]))	// signal that there won't be any other insertions to the list
	{
		printf("SetEvent failed (%d)\n", GetLastError());
		return 1;
	}

	WaitForMultipleObjects(numberOfThreads, ghThreads, TRUE, INFINITE);	// waiting for all threads to finish
	uninitList();
	for (int i = 0; i < MAXEVENTCOUNT; i++)
		CloseHandle(Events[i]);

	return noOfFilesScanned;
}