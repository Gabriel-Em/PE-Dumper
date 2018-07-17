#include "Input.h"
#include "Controller.h"

int main(int argc, char **argv)
{
	int hasRecursion, noOfThreads;
	
	if (validateArguments(argv, argc) == INVALIDARGUMENT)
	{
		printf("Usage: PE.Dumper.exe <glob_pattern> [r] [nr_threads <MIN 1, MAX 64>]");
	}
	else
	{
		int		scannedFilesCount;
		char	*path = NULL, *pattern = NULL;

		processArgvIntoPathAndPattern(&path, &pattern, argv[1]);
		if (path == NULL || pattern == NULL)
		{
			if (path != NULL)
				free(path);
			if (pattern != argv[1] && pattern != NULL)
				free(pattern);
			printf("\nMalloc error\n");
			return 0;
		}
		processOptionalParameters(argv + 1, argc - 1, &hasRecursion, &noOfThreads);
		scannedFilesCount = init(pattern, hasRecursion, path, noOfThreads);
		if (scannedFilesCount == 0)
		{
			printf("\nNo files having extension %s found.\n", argv[1]);
		}
		else
		{
			printf("\nA total of %d files scanned.\n", scannedFilesCount);
		}

		free(path);
		if (pattern != argv[1])
			free(pattern);
	}
	getchar();

	return 0;
}