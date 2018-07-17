#pragma once
#include <Windows.h>
#include <stdio.h>

// threads and events
#define MAXTHREADCOUNT			MAXIMUM_WAIT_OBJECTS
#define	MAXEVENTCOUNT			2

HANDLE							ghThreads[MAXTHREADCOUNT];
HANDLE							Events[MAXEVENTCOUNT];

// work codes
#define ERRORDOINGWORK			-1
#define WORKDONESUCCESSFULLY	0

int								(*_do_work)();

DWORD							WINAPI ThreadProc(LPVOID);
void							CreateEventsAndThreads(int noOfThreads, int(*do_work)());