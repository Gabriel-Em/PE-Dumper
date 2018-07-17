# PE Dumper
A tool that dumps PE information - intended for use with 32-Bit PE files on Windows

## How to use

- build the project to obtain the **PE.Dumper.exe** binary
- using a command prompt run `PE.Dumper.exe <glob_pattern> [r] [nr_threads <MIN 1, MAX 64>]`
where:
   - **<glob_pattern>** = filename format of files you want to dump (Ex. **"C:\\Windows\\*.exe"**)
   - **[r]** = search recursively
   - **[nr_threads]** = number of threads working simultaneously (if not specified 8 threads will be used)
   
#### *note:*
- **\<arg\>** = MANDATORY argument
- **[arg]** = OPTIONAL argument

## Example of a run:
```
Microsoft Windows [Version 10.0.17134.165]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\>PE.Dumper.exe "C:\Windows\System32\*.dll"
Thread id:  4180 ready for work...
Thread id: 15624 ready for work...
Thread id: 17244 ready for work...
Thread id:  6052 ready for work...
Thread id: 12428 ready for work...
Thread id: 13512 ready for work...
Thread id:  4180 is scanning 'C:\Windows\System32\aadauthhelper.dll'
Thread id: 17320 ready for work...
Thread id:  6584 ready for work...
Thread id: 15624 is scanning 'C:\Windows\System32\aadtb.dll'
Thread id: 17244 is scanning 'C:\Windows\System32\aadWamExtension.dll'
Thread id: 17320 is scanning 'C:\Windows\System32\AboveLockAppHost.dll'
Thread id:  6052 is scanning 'C:\Windows\System32\accessibilitycpl.dll'
Thread id: 13512 is scanning 'C:\Windows\System32\accountaccessor.dll'
Thread id: 12428 is scanning 'C:\Windows\System32\AccountsRt.dll'
Thread id:  6584 is scanning 'C:\Windows\System32\AcGenral.dll'
Thread id:  4180 is scanning 'C:\Windows\System32\AcLayers.dll'
Thread id: 17244 is scanning 'C:\Windows\System32\acledit.dll'
Thread id: 12428 is scanning 'C:\Windows\System32\aclui.dll'
Thread id:  6052 is scanning 'C:\Windows\System32\acppage.dll'
Thread id: 15624 is scanning 'C:\Windows\System32\AcSpecfc.dll'
Thread id: 13512 is scanning 'C:\Windows\System32\ActionCenter.dll'
Thread id:  6584 is scanning 'C:\Windows\System32\ActionCenterCPL.dll'
Thread id: 17320 is scanning 'C:\Windows\System32\ActivationClient.dll'
Thread id: 17244 is scanning 'C:\Windows\System32\ActivationManager.dll'
Thread id:  4180 is scanning 'C:\Windows\System32\activeds.dll'
.
.
.
Thread id:  6584 is scanning 'C:\Windows\System32\XInput9_1_0.dll'
Thread id: 15624 is scanning 'C:\Windows\System32\XInputUap.dll'
Thread id: 13512 is scanning 'C:\Windows\System32\xmlfilter.dll'
Thread id: 17244 is scanning 'C:\Windows\System32\xmllite.dll'
Thread id:  6052 is scanning 'C:\Windows\System32\xmlprovi.dll'
Thread id:  4180 is scanning 'C:\Windows\System32\xolehlp.dll'
Thread id: 17320 is scanning 'C:\Windows\System32\XpsDocumentTargetPrint.dll'
Thread id: 12428 is scanning 'C:\Windows\System32\XpsFilt.dll'
Thread id:  6584 is scanning 'C:\Windows\System32\XpsGdiConverter.dll'
Thread id: 15624 is scanning 'C:\Windows\System32\XpsPrint.dll'
Thread id: 13512 is scanning 'C:\Windows\System32\XpsRasterService.dll'
Thread id: 17244 is scanning 'C:\Windows\System32\xpsservices.dll'
Thread id:  6052 is scanning 'C:\Windows\System32\XPSSHHDR.dll'
Thread id:  4180 is scanning 'C:\Windows\System32\xwizards.dll'
Thread id: 17320 is scanning 'C:\Windows\System32\xwreg.dll'
Thread id: 12428 is scanning 'C:\Windows\System32\xwtpdui.dll'
Thread id:  6584 is scanning 'C:\Windows\System32\xwtpw32.dll'
Thread id: 15624 is scanning 'C:\Windows\System32\zipcontainer.dll'
Thread id: 13512 is scanning 'C:\Windows\System32\zipfldr.dll'
Thread id:  6052 is scanning 'C:\Windows\System32\ztrace_maps.dll'
Thread id: 17244 exiting...
Thread id:  4180 exiting...
Thread id: 17320 exiting...
Thread id: 15624 exiting...
Thread id:  6584 exiting...
Thread id: 12428 exiting...
Thread id:  6052 exiting...
Thread id: 13512 exiting...

A total of 2544 files scanned.
```

- dumps will be stored inside a **\_logs** directory located in the same place as **PE.Dumper.exe**

## Example of a log:

**log path:** C:\\\_logs\C__Windows_System32_acledit.dll.log

```
============================================================================================
                                    _IMAGE_DOS_HEADER
============================================================================================

Magic number:                                                   0X5A4D (MZ)
Bytes on last page of file:                                     144
Pages in file:                                                  3
Relocations:                                                    0
...
Offset to _IMAGE_NT_HEADERS                                     0X000000E0

============================================================================================
                                    _IMAGE_NT_HEADERS
============================================================================================

Signature:                                                      PE

============================================================================================
                                    _IMAGE_FILE_HEADER
============================================================================================

Machine:                                                        x86
Number of sections:                                             5
Time Date Stamp:                                                Wed Jan 13 19:17:41 2016

Size optional header:                                           224

============================================================================================
                                    _IMAGE_OPTIONAL_HEADER
============================================================================================

Magic:                                                          0x10b (PE32)
Address of entry point:                                         0X00001730
Image base:                                                     0X4B600000
Sections alignment in memory:                                   4096 bytes
Number of directory entries:                                    16


5 sections should be found

============================================================================================
                          _IMAGE_SECTION_HEADER [section index: 1]
============================================================================================

Section name:                                                   .text
Physical Address:                                               0X0000103A
Section size in memory:                                         4154 bytes
Virtual Address:                                                0X00001000 (RVA), 0X4B601000 (VA)
Size of initialized data on disk:                               4608 bytes
Pointer to raw data:                                            0X00000400 (RVA), 0X4B600400 (VA)

============================================================================================
                          _IMAGE_SECTION_HEADER [section index: 2]
============================================================================================

Section name:                                                   .data
Physical Address:                                               0X00000350
Section size in memory:                                         848 bytes
Virtual Address:                                                0X00003000 (RVA), 0X4B603000 (VA)
Size of initialized data on disk:                               512 bytes
Pointer to raw data:                                            0X00001600 (RVA), 0X4B601600 (VA)

============================================================================================
                          _IMAGE_SECTION_HEADER [section index: 3]
============================================================================================

Section name:                                                   .idata
Physical Address:                                               0X000002A2
Section size in memory:                                         674 bytes
Virtual Address:                                                0X00004000 (RVA), 0X4B604000 (VA)
Size of initialized data on disk:                               1024 bytes
Pointer to raw data:                                            0X00001800 (RVA), 0X4B601800 (VA)

============================================================================================
                          _IMAGE_SECTION_HEADER [section index: 4]
============================================================================================

Section name:                                                   .rsrc
Physical Address:                                               0X00000520
Section size in memory:                                         1312 bytes
Virtual Address:                                                0X00005000 (RVA), 0X4B605000 (VA)
Size of initialized data on disk:                               1536 bytes
Pointer to raw data:                                            0X00001C00 (RVA), 0X4B601C00 (VA)

============================================================================================
                          _IMAGE_SECTION_HEADER [section index: 5]
============================================================================================

Section name:                                                   .reloc
Physical Address:                                               0X00000130
Section size in memory:                                         304 bytes
Virtual Address:                                                0X00006000 (RVA), 0X4B606000 (VA)
Size of initialized data on disk:                               512 bytes
Pointer to raw data:                                            0X00002200 (RVA), 0X4B602200 (VA)

============================================================================================
                                    _IMAGE_EXPORT_DIRECTORY
============================================================================================

DLL Name:                                                       ACLEDIT.dll
Ordinal Base:                                                   1
Number of functions:                                            8
Number of names:                                                8
Time Stamp:                                                     Wed Jan 13 19:17:41 2016


--------------------------------------------------------------------------------------------
                                           Functions
--------------------------------------------------------------------------------------------

Name:                                                           DllMain
Ordinal:                                                        5
Address:                                                        0X00001350

Name:                                                           EditAuditInfo
Ordinal:                                                        1
Address:                                                        0X000014B0

Name:                                                           EditOwnerInfo
Ordinal:                                                        2
Address:                                                        0X00001430

Name:                                                           EditPermissionInfo
Ordinal:                                                        3
Address:                                                        0X000014D0

Name:                                                           FMExtensionProcW
Ordinal:                                                        4
Address:                                                        0X000014F0

Name:                                                           SedDiscretionaryAclEditor
Ordinal:                                                        6
Address:                                                        0X00001470

Name:                                                           SedSystemAclEditor
Ordinal:                                                        7
Address:                                                        0X00001490

Name:                                                           SedTakeOwnership
Ordinal:                                                        8
Address:                                                        0X00001450

============================================================================================
                                             IMPORTS
============================================================================================

============================================================================================
                                    _IMAGE_IMPORT_DESCRIPTOR
============================================================================================

DLL Name:                                                       msvcrt.dll
First Thunk:                                                    0X0000403C
Original First Thunk:                                           0X000040EC

--------------------------------------------------------------------------------------------
                                              Functions
--------------------------------------------------------------------------------------------

Function Name:                                                  _except_handler4_common
Function Name:                                                  _initterm
Function Name:                                                  malloc
Function Name:                                                  free
Function Name:                                                  _amsg_exit
Function Name:                                                  _XcptFilter
Function Name:                                                  memset

============================================================================================
                                    _IMAGE_IMPORT_DESCRIPTOR
============================================================================================

DLL Name:                                                       USER32.dll
First Thunk:                                                    0X00004030
Original First Thunk:                                           0X000040E0

--------------------------------------------------------------------------------------------
                                              Functions
--------------------------------------------------------------------------------------------

Function Name:                                                  MessageBoxW
Function Name:                                                  LoadStringW

============================================================================================
                                    _IMAGE_IMPORT_DESCRIPTOR
============================================================================================

DLL Name:                                                       KERNEL32.dll
First Thunk:                                                    0X00004000
Original First Thunk:                                           0X000040B0

--------------------------------------------------------------------------------------------
                                              Functions
--------------------------------------------------------------------------------------------

Function Name:                                                  TerminateProcess
Function Name:                                                  GetCurrentProcess
Function Name:                                                  SetUnhandledExceptionFilter
Function Name:                                                  UnhandledExceptionFilter
Function Name:                                                  GetTickCount
Function Name:                                                  GetSystemTimeAsFileTime
Function Name:                                                  GetCurrentThreadId
Function Name:                                                  GetCurrentProcessId
Function Name:                                                  QueryPerformanceCounter
Function Name:                                                  Sleep
Function Name:                                                  DisableThreadLibraryCalls
```