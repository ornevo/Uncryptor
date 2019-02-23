#pragma once
extern "C"
{
	#include <ntddk.h>
	#include <wdm.h> // for the linked list.
	DRIVER_INITIALIZE DriverEntry;
	VOID NTAPI DriverDestroy(PDRIVER_OBJECT DriverObject);
	NTSTATUS NTAPI UncryptInit(_In_ PUNICODE_STRING RegisteryPath);
	VOID NTAPI DestroyList();
	NTSTATUS NTAPI SetDefaultPath(_In_ PUNICODE_STRING RegistryPath);
	struct _UNCRYPT_INJECT_INFO
	{
		LIST_ENTRY ListEntry; // the list entry for the double linked list
		BOOLEAN IsInjected; // check if is injected.
		ULONG LoadedDlls; // flags for the dlls.
		BOOLEAN IsWoW64; // is wow64 program...
		HANDLE Process; // the key of the struct, the process id.
		PVOID LdrLoadDllRoutineAddress;// the address of LdrloadDll
	};

	_UNCRYPT_INJECT_INFO* SearchInList(HANDLE); // process handle to search in the linked list
	NTSTATUS InsertToList(PEPROCESS, HANDLE);
	VOID RemoveFromList(HANDLE); //holds the current dll loading. we need to inject to the kernel32.dll we inject to this dll because in this dll we have the apc functions.

	BOOLEAN CanInject(_UNCRYPT_INJECT_INFO*);
	NTSTATUS NTAPI UncryptorInject(_UNCRYPT_INJECT_INFO*);

}