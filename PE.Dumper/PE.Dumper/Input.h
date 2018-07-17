#pragma once
#include <Windows.h>
#include <stdio.h.>
#include <string.h>

#define DEFAULTTHREADNO		8
#define VALIDARGUMENT		1
#define INVALIDARGUMENT		0

int							validateArguments(char **argv, int argc);
void						processOptionalParameters(char **argv, int argc, int *hasRecursion, int *noOfThreads);
int							validateRecursion(char *str);
int							validateNoOfThreads(char *str);
void						processArgvIntoPathAndPattern(char **path, char **pattern, char *argv);