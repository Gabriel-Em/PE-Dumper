#pragma once
#include <Windows.h>
#include <stdio.h>
#include <time.h>
#include <winnt.h>
#include "Conversions.h"
#include "Validator.h"
#include "PE_Status.h"


#define LOGDIRECTORYNAME	"_logs"

char						logPath[MAX_PATH];

int							initLogPath();
void						log_IMAGE_DOS_HEADER(IMAGE_DOS_HEADER *img, HANDLE logHandle);
void						log_IMAGE_NT_HEADERS(IMAGE_NT_HEADERS32 *img, HANDLE logHandle);
void						log_IMAGE_FILE_HEADER(IMAGE_FILE_HEADER *img, HANDLE logHandle);
void						log_IMAGE_OPTIONAL_HEADER(IMAGE_OPTIONAL_HEADER32 *img, HANDLE logHandle);
void						log_IMAGE_SECTION_HEADER(IMAGE_SECTION_HEADER *img, BYTE code, DWORD imageBase, HANDLE logHandle);
void						log_IMAGE_EXPORT_DIRECTORY(PVOID fileBase, IMAGE_EXPORT_DIRECTORY *img, int fileSize, IMAGE_DATA_DIRECTORY *img_entry, HANDLE logHandle);
void						log_IMAGE_IMPORT_DESCRIPTOR(PVOID fileBase, IMAGE_IMPORT_DESCRIPTOR *img, int fileSize, HANDLE logHandle);
void						log_SECTION_NUMBER_INFO(int numberOfSections, HANDLE logHandle);
void						log_SECTION_HEADER_TITLE(int sectionIndex, HANDLE logHandle);
void						log_IMAGE_EXPORT_DIRECTORY_TITLE(HANDLE logHandle);
void						log_IMPORTS_GENERAL_TITLE(HANDLE logHandle);
void						log_CUSTOM_MESSAGE(char *buffer, HANDLE logHandle);