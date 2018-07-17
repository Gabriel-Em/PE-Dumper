#pragma once
#include "List.h"
#include <stdlib.h>

typedef struct		s_PE_object
{
	LIST_ENTRY		list_entry;
	char			*path;
}					PE_object;

PLIST_ENTRY			ListHead;
CRITICAL_SECTION	list_cs;

void				initList();
void				uninitList();
void				pushToList(char *path);
char				*popFromList();