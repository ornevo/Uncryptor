#pragma once

extern "C"
{
#include <wdm.h>
#include <ntddk.h>
#include <ntimage.h>
	enum UNCRYPT_DLL_LOAD_FLAGS
	{
		UNCRYPT_DLL_LOAD_NOTHING = 0x0000,
		UNCRYPT_DLL_LOAD_NTDLL_WOW64_DLL = 0x0001,
		UNCRYPT_DLL_LOAD_KERNEL32_DLL = 0x0002,
		UNCRYPT_DLL_LOAD_WOW64_DLL = 0x0004,
		UNCRYPT_DLL_LOAD_WOW64CPU_DLL = 0x0008,
		UNCRYPT_DLL_LOAD_WOW64WIN_DLL = 0x0010,
		UNCRYPT_DLL_LOAD_NTDLL_32BIT_DLL = 0X0020,
	};

	struct UNCRYPT_DLL_DESCRIPTOR
	{
		UNICODE_STRING Path;
		UNCRYPT_DLL_LOAD_FLAGS Flags;
	};

	UNCRYPT_DLL_DESCRIPTOR DLLS_DESCRIPTORS[] = {
		{RTL_CONSTANT_STRING(L"\\SysWow64\\ntdll.dll"), UNCRYPT_DLL_LOAD_NTDLL_WOW64_DLL},
		{RTL_CONSTANT_STRING(L"\\System32\\kernel32.dll"), UNCRYPT_DLL_LOAD_KERNEL32_DLL},
		{ RTL_CONSTANT_STRING(L"\\System32\\wow64.dll"), UNCRYPT_DLL_LOAD_WOW64_DLL},
		{ RTL_CONSTANT_STRING(L"\\System32\\wow64cpu.dll"), UNCRYPT_DLL_LOAD_WOW64CPU_DLL },
		{ RTL_CONSTANT_STRING(L"\\System32\\wow64win.dll"), UNCRYPT_DLL_LOAD_WOW64WIN_DLL },
		{ RTL_CONSTANT_STRING(L"\\System32\\ntdll.dll"), UNCRYPT_DLL_LOAD_NTDLL_32BIT_DLL}
	};

	NTKERNELAPI
		PVOID
		NTAPI
		PsGetProcessWow64Process(
			_In_ PEPROCESS Process
		);
	NTKERNELAPI
		BOOLEAN
		NTAPI
		PsIsProtectedProcess(
			_In_ PEPROCESS Process
		);
	NTKERNELAPI
		PVOID
		NTAPI
		RtlFindExportedRoutineByName(
			_In_ PVOID ImageBase,
			_In_ PCCH RoutineNam
		);
	NTSYSAPI
		NTSTATUS
		NTAPI
		RtlDuplicateUnicodeString(
			_In_ ULONG Flags,
			_In_ PUNICODE_STRING StringIn,
			_Out_ PUNICODE_STRING StringOut
		);

	#define UNCRYPT_MEMORY_TAG 'unc' // for the ExAllocatePoolWithTag
	#define RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE (0x00000001)
	#define RTL_DUPLICATE_UNICODE_STRING_ALLOCATE_NULL_STRING (0x00000002)

	LIST_ENTRY g_head_of_linked_list;
	UNICODE_STRING DLL_X32_PATH_TO_INJECT;
	UNICODE_STRING DLL_X64_PATH_TO_INJECT;

# define UncryptDbg(Format, ...)  \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID,         \
               DPFLTR_INFO_LEVEL,          \
               Format,                      \
               __VA_ARGS__)





	//
	// Taken from ReactOS, used by InjpInitializeDllPaths.
	//

	typedef union
	{
		WCHAR Name[sizeof(ULARGE_INTEGER) / sizeof(WCHAR)];
		ULARGE_INTEGER Alignment;
	} ALIGNEDNAME;

	//
	// DOS Device Prefix \??\
	//

	ALIGNEDNAME ObpDosDevicesShortNamePrefix = { { L'\\', L'?', L'?', L'\\' } };
	UNICODE_STRING ObpDosDevicesShortName = {
		sizeof(ObpDosDevicesShortNamePrefix), // Length
		sizeof(ObpDosDevicesShortNamePrefix), // MaximumLength
		(PWSTR)&ObpDosDevicesShortNamePrefix  // Buffer
	};

	NTSTATUS
		NTAPI
		JoinPath(
			_In_ PUNICODE_STRING Directory,
			_In_ PUNICODE_STRING Filename,
			_Inout_ PUNICODE_STRING FullPath
		)
	{
		UNICODE_STRING UnicodeBackslash = RTL_CONSTANT_STRING(L"\\");

		BOOLEAN DirectoryEndsWithBackslash = Directory->Length > 0 &&
			Directory->Buffer[Directory->Length - 1] == L'\\';

		if (FullPath->MaximumLength < Directory->Length ||
			FullPath->MaximumLength - Directory->Length -
			(!DirectoryEndsWithBackslash ? 1 : 0) < Filename->Length)
		{
			return STATUS_DATA_ERROR;
		}

		RtlCopyUnicodeString(FullPath, Directory);

		if (!DirectoryEndsWithBackslash)
		{
			RtlAppendUnicodeStringToString(FullPath, &UnicodeBackslash);
		}

		RtlAppendUnicodeStringToString(FullPath, Filename);

		return STATUS_SUCCESS;
	}
}
