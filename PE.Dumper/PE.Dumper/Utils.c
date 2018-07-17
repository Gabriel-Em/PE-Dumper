#include "Utils.h"

char *combinePath(char *path, char* fileName)
{
	size_t lenPath, lenFileName;
	char *completePath;

	lenPath = strlen(path);
	lenFileName = strlen(fileName);

	completePath = (char*)malloc(sizeof(char) * (lenPath + lenFileName + 2));
	if (!completePath)
		return NULL;

	strcpy_s(completePath, (lenPath + lenFileName + 2), path);
	completePath[lenPath] = '\\';
	completePath[lenPath + 1] = '\0';
	strcat_s(completePath, (lenPath + lenFileName + 2), fileName);

	return completePath;
}

char *pathToFileName(char *path)
{
	size_t	len, i;
	char	*fileName;

	len = strlen(path);
	fileName = (char*)malloc(sizeof(char) * (5 + len));

	if (!fileName)
		return NULL;

	i = 0;
	while (path[i])
	{
		if (path[i] == '\\' || path[i] == ':')
			fileName[i] = '_';
		else
			fileName[i] = path[i];
		i++;
	}
	fileName[i] = '\0';
	strcat_s(fileName, 5 + len, ".log");

	return fileName;
}