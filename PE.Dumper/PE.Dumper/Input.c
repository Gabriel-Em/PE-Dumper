#include "Input.h"

int validateRecursion(char *str)
{
	if (strcmp(str, "r") == 0)
		return VALIDARGUMENT;
	return INVALIDARGUMENT;
}

int validateNoOfThreads(char *str)
{
	int no;

	no = atoi(str);

	if (no >= 1 && no <= MAXIMUM_WAIT_OBJECTS)
		return VALIDARGUMENT;
	return INVALIDARGUMENT;
}

void processOptionalParameters(char **argv, int argc, int *hasRecursion, int *noOfThreads)
{
	*hasRecursion = 0;
	*noOfThreads = DEFAULTTHREADNO;

	if (argc == 1)
		return;
	if (argc == 2)
	{
		if (validateRecursion(argv[1]))
		{
			*hasRecursion = 1;
		}
		else
		{
			*noOfThreads = atoi(argv[1]);
		}
		return;
	}
	*hasRecursion = 1;
	if (validateNoOfThreads(argv[1]))
	{
		*noOfThreads = atoi(argv[1]);
	}
	else
	{
		*noOfThreads = atoi(argv[2]);
	}
}

int validateArguments(char **argv, int argc)
{
	if (argc < 2 || argc > 4)
		return INVALIDARGUMENT;

	if (argc == 2)
		return VALIDARGUMENT;

	if (argc == 3)
	{
		if (validateRecursion(argv[2]) || validateNoOfThreads(argv[2]))
			return VALIDARGUMENT;
		return INVALIDARGUMENT;
	}

	if (validateRecursion(argv[2]) && validateNoOfThreads(argv[3]) || validateNoOfThreads(argv[2]) && validateRecursion(argv[3]))
		return VALIDARGUMENT;
	return INVALIDARGUMENT;
}

void processArgvIntoPathAndPattern(char **path, char **pattern, char *argv)
{
	int i = 0, pathDelimiter = -1, len = 0;

	while (argv[len])
	{
		if (argv[len] == '\\')
			pathDelimiter = len;
		len++;
	}

	if (pathDelimiter == -1)
	{
		*path = (char*)malloc(sizeof(char) * 3);
		if (*path == NULL)
			return;
		(*path)[0] = '.';
		(*path)[1] = '\\';
		(*path)[2] = '\0';
		*pattern = argv;
	}
	else
	{
		*path = (char*)malloc(sizeof(char) * (pathDelimiter + 2));
		if (*path == NULL)
			return;
		for (i = 0; i <= pathDelimiter; i++)
			(*path)[i] = argv[i];
		(*path)[i] = '\0';

		*pattern = (char*)malloc(sizeof(char) * (len - pathDelimiter));
		if (*pattern == NULL)
			return;
		i = 0;
		pathDelimiter++;
		while (argv[pathDelimiter])
			(*pattern)[i++] = argv[pathDelimiter++];
		(*pattern)[i] = '\0';
	}
}