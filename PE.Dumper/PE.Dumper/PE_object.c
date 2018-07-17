#pragma once
#include "PE_object.h"

void	initList()
{
	ListHead = (PLIST_ENTRY)malloc(sizeof(LIST_ENTRY));
	InitializeListHead(ListHead);
	InitializeCriticalSection(&list_cs);
}

void	pushToList(char *path)
{
	PE_object* mo = (PE_object*)malloc(sizeof(PE_object));
	if (!mo)
		return;
	mo->path = path;
	InterlockedInsertTailList(ListHead, &(mo->list_entry), &list_cs);
}

char	*popFromList()
{
	if (IsListEmpty(ListHead))
	{
		return NULL;
	}

	LIST_ENTRY		*first;
	PE_object		*object;
	char			*path;

	first = ListHead->Flink;
	object = (PE_object*)CONTAINING_RECORD(first, PE_object, list_entry);

	if (object)
	{
		path = object->path;
		RemoveHeadList(ListHead);
		free(object);
	}
	else
		path = NULL;


	return path;
}

void	uninitList()
{
	if (ListHead)
		free(ListHead);
	DeleteCriticalSection(&list_cs);
}