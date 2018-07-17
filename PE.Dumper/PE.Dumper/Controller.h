#pragma once

#include <Windows.h>
#include <stdio.h>
#include "Validator.h"
#include "Log.h"
#include <winnt.h>
#include "Conversions.h"
#include "PE_Status.h"
#include "PE_object.h"
#include "Threads.h"
#include "Utils.h"

int init(char *pattern, int recursive, char *dirPath, int numberOfThreads);