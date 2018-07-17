#include "Threads.h"

void CreateEventsAndThreads(int noOfThreads, int(*do_work)())
{
	int i;
	DWORD dwThreadID;
	BOOL	manualReset;

	_do_work = do_work;

	for (i = 0; i < MAXEVENTCOUNT; i++)
	{
		if (i == 0)
			manualReset = FALSE;
		else
			manualReset = TRUE;

		Events[i] = CreateEvent(
			NULL,
			manualReset,
			FALSE,
			NULL
		);

		if (Events[i] == NULL)
		{
			printf("CreateEvent failed (%d)\n", GetLastError());
			return;
		}
	}

	for (i = 0; i < noOfThreads; i++)
	{
		ghThreads[i] = CreateThread(
			NULL,
			0,
			ThreadProc,
			NULL,
			0,
			&dwThreadID);

		if (ghThreads[i] == NULL)
		{
			printf("CreateThread failed (%d)\n", GetLastError());
			return;
		}
	}
}

DWORD WINAPI ThreadProc(LPVOID lpParam)
{
	DWORD dwWaitResult;
	BYTE termination = 0;

	UNREFERENCED_PARAMETER(lpParam);

	printf("Thread id: %5d ready for work...\n", GetCurrentThreadId());

	while (!termination)
	{
		dwWaitResult = WaitForMultipleObjects(
			MAXEVENTCOUNT,
			Events,
			FALSE,
			INFINITE);
		switch (dwWaitResult)
		{
		case WAIT_OBJECT_0:									// new data added to list
			_do_work();
			break;
		case WAIT_OBJECT_0 + 1:								// all data added - work will be done until list is empty
			if (_do_work() == ERRORDOINGWORK)
				termination = 1;
			break;
		case WAIT_FAILED:
			break;
		default:
			break;
		}
	}
	printf("Thread id: %5d exiting...\n", GetCurrentThreadId());
	return 1;
}