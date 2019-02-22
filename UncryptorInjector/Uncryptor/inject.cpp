#include "inject.h"
#include "hook.h"
#include "constants.h"
#include "apc_injecting.h"

VOID
NTAPI
DriverDestroy(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UncryptDbg("[UncryptInjector] Destroying Driver...\n");
	PsRemoveLoadImageNotifyRoutine(&ImageNotifyHook);
	PsSetCreateProcessNotifyRoutineEx(&ProcessNotifyHook, TRUE);
	DestroyList();
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegisteryPath)
{
	UncryptDbg("[UncryptInjector] Init Driver...\n");
	DriverObject->DriverUnload = &DriverDestroy;
	NTSTATUS Status = UncryptInit(RegisteryPath);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	return STATUS_SUCCESS;
}



NTSTATUS NTAPI UncryptInit(_In_ PUNICODE_STRING RegisteryPath)
{
	InitializeListHead(&g_head_of_linked_list);
	SetDefaultPath(RegisteryPath);
	NTSTATUS Status;
	Status = PsSetCreateProcessNotifyRoutineEx(&ProcessNotifyHook, FALSE);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	Status = PsSetLoadImageNotifyRoutineEx(&ImageNotifyHook, 0);
	if (!NT_SUCCESS(Status))
	{
		PsSetCreateProcessNotifyRoutineEx(&ProcessNotifyHook, TRUE);
	}
	return Status;
}


VOID NTAPI DestroyList()
{
	PLIST_ENTRY Next = g_head_of_linked_list.Flink;
	while (Next != &g_head_of_linked_list)
	{
		_UNCRYPT_INJECT_INFO *info = CONTAINING_RECORD(Next, _UNCRYPT_INJECT_INFO, ListEntry);
		Next = Next->Flink;
		ExFreePoolWithTag(info, UNCRYPT_MEMORY_TAG);
	}
}

VOID NTAPI SetDefaultPath(_In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS Status;
	UNICODE_STRING ValueImagePath = RTL_CONSTANT_STRING(L"ImagePath");
	OBJECT_ATTRIBUTES object_attributes;
	InitializeObjectAttributes(&object_attributes,
		RegistryPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);
	HANDLE MyHandle;
	Status = ZwOpenKey(&MyHandle, KEY_READ, &object_attributes);
	if (!NT_SUCCESS(Status))
	{
		return;
	}
	
	UCHAR KeyValueInformationBuffer[sizeof(KEY_VALUE_FULL_INFORMATION) + sizeof(WCHAR) * 128];
	PKEY_VALUE_FULL_INFORMATION KeyValueInformation = (PKEY_VALUE_FULL_INFORMATION)KeyValueInformationBuffer;
	ULONG ResultSize;
	Status = ZwQueryValueKey(MyHandle, &ValueImagePath, KeyValueFullInformation, KeyValueInformation, sizeof(KeyValueInformationBuffer), &ResultSize);
	ZwClose(MyHandle);

	if (!NT_SUCCESS(Status) || KeyValueInformation->Type != REG_EXPAND_SZ)
	{
		return;
	}
	PWCHAR ImagePathValue = (PWCHAR)((PUCHAR)KeyValueInformation + KeyValueInformation->DataOffset);
	ULONG  ImagePathValueLength = KeyValueInformation->DataLength;

	if (*(PULONGLONG)(ImagePathValue) == ObpDosDevicesShortNamePrefix.Alignment.QuadPart)
	{
		ImagePathValue += ObpDosDevicesShortName.Length / sizeof(WCHAR);
		ImagePathValueLength -= ObpDosDevicesShortName.Length;
	}
	PWCHAR LastBackslash = wcsrchr(ImagePathValue, L'\\');
	if (!LastBackslash)
	{
		return;
	}
	*LastBackslash = UNICODE_NULL;
	UNICODE_STRING Directory;
	RtlInitUnicodeString(&Directory, ImagePathValue);

#define UNCRYPT_DLL_X64_NAME L"Uncryptdllx64.dll"
	UNICODE_STRING InjDllNamex64 = RTL_CONSTANT_STRING(UNCRYPT_DLL_X64_NAME);
	JoinPath(&Directory, &InjDllNamex64, &DLL_X64_PATH_TO_INJECT);
	UncryptDbg("[UncryptorInject] Dll path (x64): '%wZ'\n", DLL_X64_PATH_TO_INJECT);
#define UNCRYPT_DLL_X86_NAME L"Uncryptdllx86.dll"
	UNICODE_STRING InjDllNamex86 = RTL_CONSTANT_STRING(UNCRYPT_DLL_X86_NAME);
	JoinPath(&Directory, &InjDllNamex86, &DLL_X32_PATH_TO_INJECT);
	UncryptDbg("[UncryptorInject] Dll path (x64): '%wZ'\n", DLL_X32_PATH_TO_INJECT);

}



////////////////////////////////////////////////////////////////////////////////
////////////////////////////// HOOKING FUNCTIONS ///////////////////////////////
////////////////////////////////////////////////////////////////////////////////

VOID ProcessNotifyHook(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	UncryptDbg("[UncryptorInjector] Process Created: %d\n", (ULONG)(ULONG_PTR)ProcessId);
	if (CreateInfo) //Creating
	{
		InsertToList(Process,ProcessId);
	}
	else //exiting
	{
		RemoveFromList(ProcessId);
	}
}

VOID ImageNotifyHook(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
	_UNCRYPT_INJECT_INFO *info = SearchInList(ProcessId);
	if (!info || info->IsInjected)
	{
		return;
	}
	if (info->IsWoW64)
	{
		// For now dont handle is wow64.
		// TODO: remove the value from the linked list.
		return; 
	}
	if (PsIsProtectedProcess(PsGetCurrentProcess()))
	{
		// dont inject into protected process.
		// TODO: remove the value from linked list.
		return;
	}
	UncryptDbg("[UncryptInjector] Image notify on process %d\n", (ULONG)(ULONG_PTR)ProcessId);
	if (!CanInject(info))
	{
		for (LONG index = 0; index < RTL_NUMBER_OF(DLLS_DESCRIPTORS); index++)
		{
			PUNICODE_STRING UnicodeString = &DLLS_DESCRIPTORS[index].Path;
			if (RtlSuffixUnicodeString(UnicodeString, FullImageName, TRUE))
			{
				PVOID LdrLoadLibFunction = RtlFindExportedRoutineByName(ImageInfo->ImageBase, "LdrLoadDll");
				LONG DllFlag = DLLS_DESCRIPTORS[index].Flags;
				info->LoadedDlls |= DllFlag;
				
				if (DllFlag == UNCRYPT_DLL_LOAD_NTDLL_32BIT_DLL)
				{
					info->LdrLoadDllRoutineAddress = LdrLoadLibFunction;
				}
			}
		}
	}
	else
	{
		//DO THE APC INJECTION
		UncryptDbg("[UncryptInjector] Injecting (PID: %d)\n", (ULONG)(ULONG_PTR)ProcessId);

		info->IsInjected = TRUE;
	}
}

BOOLEAN CanInject(_UNCRYPT_INJECT_INFO *info)
{
	ULONG RequiredDlls = UNCRYPT_DLL_LOAD_NTDLL_32BIT_DLL;

	//TODO add code for the 64 bits.

	return (RequiredDlls & info->LoadedDlls) == RequiredDlls;
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////// LINKED LIST FUNCTIONS ///////////////////////////
////////////////////////////////////////////////////////////////////////////////

_UNCRYPT_INJECT_INFO* SearchInList(HANDLE Process)
{
	LIST_ENTRY *Next = g_head_of_linked_list.Flink;
	while (Next != &g_head_of_linked_list) // end of the list, loop back.
	{
		_UNCRYPT_INJECT_INFO *InjectInfo = CONTAINING_RECORD(Next, _UNCRYPT_INJECT_INFO, ListEntry);
		if (InjectInfo->Process == Process)
		{
			return InjectInfo;
		}
		Next = Next->Flink;
	}
	return NULL;
}


NTSTATUS InsertToList(PEPROCESS ProcessFrame, HANDLE Process)
{
	_UNCRYPT_INJECT_INFO *InjectInfo;
	InjectInfo = (_UNCRYPT_INJECT_INFO*)ExAllocatePoolWithTag(NonPagedPool, sizeof(_UNCRYPT_INJECT_INFO), UNCRYPT_MEMORY_TAG);
	if (!InjectInfo)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlZeroMemory(InjectInfo, sizeof(_UNCRYPT_INJECT_INFO));
	InjectInfo->Process = Process;
	InjectInfo->IsInjected = FALSE;
	if (PsGetProcessWow64Process(ProcessFrame))
	{
		InjectInfo->IsWoW64 = TRUE;
	}
	else
	{
		InjectInfo->IsWoW64 = FALSE;
	}
	InsertTailList(&g_head_of_linked_list, &InjectInfo->ListEntry);
	return STATUS_SUCCESS;
}

VOID RemoveFromList(HANDLE Process)
{
	_UNCRYPT_INJECT_INFO *InjectInfo = SearchInList(Process);
	RemoveEntryList(&InjectInfo->ListEntry);

	ExFreePoolWithTag(InjectInfo, UNCRYPT_MEMORY_TAG);
}


////////////////////////////////////////////////////////////////////////////////
////////////////////////////// APC FUNCTIONS ///////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

NTSTATUS NTAPI UncryptApcQueue(KPROCESSOR_MODE ApcMode, PKNORMAL_ROUTINE NormalRoutine, PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	PKAPC Apc = (PKAPC)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(KAPC), UNCRYPT_MEMORY_TAG);
	if (!Apc)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	KeInitializeApc(
		Apc,
		PsGetCurrentThread(),
		OriginalApcEnvironment,
		&UncryptInjectApcKernelRoutine,
		NULL,
		NormalRoutine,
		ApcMode,
		NormalContext
	);

	BOOLEAN Inserted = KeInsertQueueApc(
		Apc,
		SystemArgument1,
		SystemArgument2,
		0
	);

	if (!Inserted)
	{
		ExFreePoolWithTag(Apc, UNCRYPT_MEMORY_TAG);
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}


VOID
NTAPI
UncryptInjectApcNormalRoutine(
	_In_ PVOID NormalContext,
	_In_ PVOID SystemArgument1,
	_In_ PVOID SystemArgument2
)
{
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);
	_UNCRYPT_INJECT_INFO *info = (_UNCRYPT_INJECT_INFO*)NormalContext;
	UncryptorInject(info);

}

VOID
NTAPI
UncryptInjectApcKernelRoutine(
	PKAPC Apc, 
	PKNORMAL_ROUTINE * NormalRoutine,
	PVOID * NormalContext, 
	PVOID * SystemArgument1, 
	PVOID * SystemArgument2
)
{
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(NormalRoutine);


	ExFreePoolWithTag(Apc, UNCRYPT_MEMORY_TAG);
}

NTSTATUS
NTAPI
UncryptorInject(_UNCRYPT_INJECT_INFO* info)
{
	NTSTATUS Status;
	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(
		&ObjectAttributes,
		NULL,
		OBJ_KERNEL_HANDLE,
		NULL,
		NULL
	);
	HANDLE SectionHandle;
	SIZE_T SectionSize = PAGE_SIZE;
	LARGE_INTEGER MaximumSize;
	MaximumSize.QuadPart = SectionSize;
	Status = ZwCreateSection(&SectionHandle,
		GENERIC_READ | GENERIC_WRITE,
		&ObjectAttributes,
		&MaximumSize,
		PAGE_EXECUTE_READWRITE,
		SEC_COMMIT,
		NULL);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}
	InjectThunkLess(info, SectionHandle, SectionSize);
	return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
InjectThunkLess(
	_UNCRYPT_INJECT_INFO *InjectionInfo,
	HANDLE SectionHandle,
	SIZE_T SectionSize)
{
	NTSTATUS Status;
	PVOID AddressOfSection;
	Status = ZwMapViewOfSection(SectionHandle,
		ZwCurrentProcess(),
		&AddressOfSection,
		0,
		PAGE_SIZE,
		NULL,
		&SectionSize,
		ViewUnmap,
		0,
		PAGE_READWRITE
	);

	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	PUNICODE_STRING DllPath = (PUNICODE_STRING)(AddressOfSection);
	PWCHAR DllPathBuffer = (PWCHAR)((PWCHAR)DllPath + sizeof(UNICODE_STRING));
	if (InjectionInfo->IsWoW64)
	{
		RtlCopyMemory(DllPathBuffer,
			DLL_X32_PATH_TO_INJECT.Buffer,
			DLL_X32_PATH_TO_INJECT.Length);
	}
	else
	{
		RtlCopyMemory(DllPathBuffer,
			DLL_X64_PATH_TO_INJECT.Buffer,
			DLL_X64_PATH_TO_INJECT.Length);
	}

	RtlInitUnicodeString(DllPath, DllPathBuffer);
	Status = UncryptApcQueue(
		UserMode,
		(PKNORMAL_ROUTINE)(ULONG_PTR)InjectionInfo->LdrLoadDllRoutineAddress,
		NULL,
		NULL,
		DllPath
	);

	//
	// 4th param. of LdrLoadDll (BaseAddress) is actually an output parameter.
	//
	// When control is transferred to the KiUserApcDispatcher routine of the
	// 64-bit ntdll.dll, the RSP points to the CONTEXT structure which might
	// be eventually provided to the ZwContinue function (in case this APC
	// dispatch will be routed to the Wow64 subsystem).
	//
	// Also, the value of the RSP register is moved to the R9 register before
	// calling the KiUserCallForwarder function.  The KiUserCallForwarder
	// function actually passes this value of the R9 register down to the
	// NormalRoutine as a "hidden 4th parameter".
	//
	// Because LdrLoadDll writes to the provided address, it'll actually
	// result in overwrite of the CONTEXT.P1Home field (the first field of
	// the CONTEXT structure).
	//
	// Luckily for us, this field is only used in the very early stage of
	// the APC dispatch and can be overwritten without causing any troubles.
	//
	// For excellent explanation, see:
	// https://www.sentinelone.com/blog/deep-hooks-monitoring-native-execution-wow64-applications-part-2
	//
	return Status;
}