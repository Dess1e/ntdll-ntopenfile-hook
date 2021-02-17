#include <iostream>
#include <stdexcept>
#include <Windows.h>

#include "win32.h"

typedef NTSTATUS(*fNtOpenFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);

fNtOpenFile g_newNtOpenFile = nullptr;

void PrintConsole(const wchar_t*);

NTSTATUS hkNtOpenFile(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    ULONG              ShareAccess,
    ULONG              OpenOptions
) {

    auto status = g_newNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
    wchar_t buf[255] = { 0 };
    wsprintf(
        buf,
        L"NtOpenFile: %s (%#X)\n",
        std::wstring(
            ObjectAttributes->ObjectName->Buffer,
            ObjectAttributes->ObjectName->Length
        ).c_str(),
        status
    );
    PrintConsole(buf);
    return status;
}

#pragma pack(push, 1)
struct jmp_far_bytes {
    unsigned short _movabs_rax = 47176; // movabs rax, imm
    __int64 jmp_addr = 0; // 8byte imm value
    unsigned short _jmp_rax = 57599; // jmp rax
};
#pragma pack(pop)

void HookNtOpenFile() {
    HMODULE library_handle = LoadLibrary(L"NTDLL.DLL");
    if (!library_handle)
        throw std::runtime_error("Couldn't get NTDLL.DLL handle");
    fNtOpenFile proc_addr = (fNtOpenFile)GetProcAddress(library_handle, "NtOpenFile");

    // rm page write protection so we can add jmp to real NtOpenFile
    // and get read permissions
    DWORD old_protect = 0;
    VirtualProtect(proc_addr, 128, PAGE_EXECUTE_READWRITE, &old_protect);

    // make a copy of real ntopenfile somewhere, 128 bytes should be enough
    fNtOpenFile newNtOpenFile = (fNtOpenFile)VirtualAlloc(nullptr, 128, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!newNtOpenFile)
        throw std::runtime_error("Couldn't allocate some rwx memory");
    memcpy(newNtOpenFile, proc_addr, 128);
    // save ptr to copy of ntopenfile
    g_newNtOpenFile = newNtOpenFile;

    // prepare shellcode
    auto jmp_struct = new jmp_far_bytes;
    jmp_struct->jmp_addr = (__int64)hkNtOpenFile;

    // fill old instruction with nops
    memset(proc_addr, 0x90, 16);
    // then put shellcode at the start of old ntopenfile
    memcpy(proc_addr, jmp_struct, sizeof jmp_far_bytes);

    delete jmp_struct;
}

void UnhookNtOpenFile() {
    HMODULE library_handle = LoadLibrary(L"NTDLL.DLL");
    if (!library_handle)
        throw std::runtime_error("Couldn't get NTDLL.DLL handle for unhooking");
    fNtOpenFile proc_addr = (fNtOpenFile)GetProcAddress(library_handle, "NtOpenFile");
    memcpy(proc_addr, g_newNtOpenFile, 16);
    VirtualFree(g_newNtOpenFile, 0, MEM_RELEASE);
    g_newNtOpenFile = nullptr;
}

void PrintConsole(const wchar_t* buf) {
    WriteConsole(
        GetStdHandle(STD_OUTPUT_HANDLE),
        buf,
        wcslen(buf),
        0, 0
    );
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: {
        AllocConsole();
        HookNtOpenFile();
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

