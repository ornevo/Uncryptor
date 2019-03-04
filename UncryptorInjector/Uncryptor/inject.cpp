#include "inject.h"
#include "hook.h"
#include "constants.h"
#include "apc_injecting.h"

#define UNCRYPT_DLL_X64_NAME L"UncryptorDLL.dll"
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
	RtlFreeUnicodeString(&DLL_X64_PATH_TO_INJECT);
	DestroyList();
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegisteryPath)
{
	UncryptDbg("[UncryptInjector] Init Driver...\n");
	DriverObject->DriverUnload = &DriverDestroy;
	NTSTATUS Status = UncryptInit(RegisteryPath);
	if (!NT_SUCCESS(Status))
	{
		UncryptDbg("[UncryptInjector] Error at setting up the Uncrypt...\n");
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

	Status = PsSetLoadImageNotifyRoutine(&ImageNotifyHook);
	if (!NT_SUCCESS(Status))
	{
		PsSetCreateProcessNotifyRoutineEx(&ProcessNotifyHook, TRUE);
	}
	return STATUS_SUCCESS;
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

NTSTATUS NTAPI SetDefaultPath(_In_ PUNICODE_STRING RegistryPath)
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
		return Status;
	}

	UCHAR KeyValueInformationBuffer[sizeof(KEY_VALUE_FULL_INFORMATION) + sizeof(WCHAR) * 128];
	PKEY_VALUE_FULL_INFORMATION KeyValueInformation = (PKEY_VALUE_FULL_INFORMATION)KeyValueInformationBuffer;
	ULONG ResultSize;
	Status = ZwQueryValueKey(MyHandle, &ValueImagePath, KeyValueFullInformation, KeyValueInformation, sizeof(KeyValueInformationBuffer), &ResultSize);
	ZwClose(MyHandle);

	if (!NT_SUCCESS(Status) || KeyValueInformation->Type != REG_EXPAND_SZ || KeyValueInformation->DataLength < sizeof(ObpDosDevicesShortName))
	{
		return Status;
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
		return STATUS_DATA_ERROR;
	}
	*LastBackslash = UNICODE_NULL;
	UNICODE_STRING Directory;

	ULONG Flags = RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE
		| RTL_DUPLICATE_UNICODE_STRING_ALLOCATE_NULL_STRING;

	RtlInitUnicodeString(&Directory, ImagePathValue);
	UNICODE_STRING InjDllNamex64 = RTL_CONSTANT_STRING(UNCRYPT_DLL_X64_NAME);
	UNICODE_STRING tmp;
	WCHAR DLL_X64_BUFF[128];
	tmp.Length = 0;
	tmp.MaximumLength = 128;
	tmp.Buffer = DLL_X64_BUFF;
	JoinPath(&Directory, &InjDllNamex64, &tmp);
	RtlDuplicateUnicodeString(Flags,
		&tmp,
		&DLL_X64_PATH_TO_INJECT);

	UncryptDbg("[UncryptorInjector] Dll path (x64): '%wZ'\n", &DLL_X64_PATH_TO_INJECT);
	return STATUS_SUCCESS;
}



////////////////////////////////////////////////////////////////////////////////
////////////////////////////// HOOKING FUNCTIONS ///////////////////////////////
////////////////////////////////////////////////////////////////////////////////

VOID ProcessNotifyHook(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{

	if (CreateInfo) //Creating
	{
		InsertToList(Process, ProcessId);
	}
	else //exiting
	{
		RemoveFromList(ProcessId);
	}
}

VOID ImageNotifyHook(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
	_UNCRYPT_INJECT_INFO *info = SearchInList(ProcessId);
	if (!info)
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
		if (!info->IsInjected)
		{
			//DO THE APC INJECTION
			if (!NT_SUCCESS(UncryptApcQueue(KernelMode,
				&UncryptInjectApcNormalRoutine,
				info,
				NULL,
				NULL)))
			{
				UncryptDbg("[UncryptInjector] UncryptApcQueue Error\n ");
			}
			info->IsInjected = TRUE;
		}
		else
		{
			if (RtlSuffixUnicodeString(&DLL_UNCRYPTOR.Path, FullImageName, TRUE) && !info->IsLoaded)
			{
				PVOID HookFunctionAddress = RtlFindExportedRoutineByName(ImageInfo->ImageBase, "HookFunctions");
				info->HookAllRoutineAddress = HookFunctionAddress;
				UncryptDbg("[UncryptInjector] Image UncryptDll found in process %p\n", HookFunctionAddress);
				info->IsLoaded = TRUE;
				IterateOverFlagsAndNotify(info);
			}
			else if(info->IsLoaded)
			{
				//UncryptDbg("[UncryptInjector] Image notify on process %wZ\n", FullImageName);
				
				for (ULONG index = 0; index < RTL_NUMBER_OF(DLLS_DESCRIPTORS); index++)
				{
					if (DLLS_DESCRIPTORS[index].NeedToNotify)
					{
						NotifyUncryptorDLL(info, DLLS_DESCRIPTORS[index].Flags);
					}
				}
			}
		}
	}
}

BOOLEAN CanInject(_UNCRYPT_INJECT_INFO *info)
{
	ULONG RequiredDlls = UNCRYPT_DLL_LOAD_NTDLL_32BIT_DLL | UNCRYPT_DLL_LOAD_KERNEL32_DLL | UNCRYPT_DLL_LOAD_KERNELBASE_DLL;
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
	if (InjectInfo)
	{
		RemoveEntryList(&InjectInfo->ListEntry);

		ExFreePoolWithTag(InjectInfo, UNCRYPT_MEMORY_TAG);
	}
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
	if (!NT_SUCCESS(UncryptorInject(info)))
	{
		UncryptDbg("[UncryptInjector] UncryptInjectApcNormalRoutine Error at UncryptInject\n ");
	}

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
	if (!NT_SUCCESS(Status = InjectThunkLess(info, SectionHandle, SectionSize)))
	{
		UncryptDbg("[UncryptInjector] Error at inject thunk less: %ld\n ", Status);
	}
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
	PVOID AddressOfSection = NULL;
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
		UncryptDbg("[UncryptInjector] Error at ZwMapViewOfSection: %X\n ", Status);
		return Status;
	}

	PUNICODE_STRING DllPath = (PUNICODE_STRING)(AddressOfSection);
	PWCHAR DllPathBuffer = (PWCHAR)((PWCHAR)DllPath + sizeof(UNICODE_STRING));
	RtlCopyMemory(DllPathBuffer,
		DLL_X64_PATH_TO_INJECT.Buffer,
		DLL_X64_PATH_TO_INJECT.Length);
	
	RtlInitUnicodeString(DllPath, DllPathBuffer);
	Status = UncryptApcQueue(
		UserMode,
		(PKNORMAL_ROUTINE)(ULONG_PTR)InjectionInfo->LdrLoadDllRoutineAddress,
		NULL,
		NULL,
		DllPath
	);
	
	UncryptDbg("[UncryptInjector] Finish Injecting\n");
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

////////////////////////////////////////////////////////////////////////////////////
////////////////////////////// Hooking functions ///////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////

NTSTATUS NotifyUncryptorDLL(_UNCRYPT_INJECT_INFO *info, ULONG flag)
{
	return UncryptApcQueue(KernelMode,
		&UncryptCallHookMethodNormalRouting,
		info,
		(PVOID)flag,
		NULL);
}

VOID IterateOverFlagsAndNotify(_UNCRYPT_INJECT_INFO *info)
{
	ULONG flags = 0;
	for (LONG index = 0; index < RTL_NUMBER_OF(DLLS_DESCRIPTORS); index++)
	{
		LONG DllFlag = DLLS_DESCRIPTORS[index].Flags;
		if (DLLS_DESCRIPTORS[index].NeedToNotify)
		{
			flags |= DllFlag;
		}
	}
	NotifyUncryptorDLL(info, flags);
}

VOID
NTAPI
UncryptCallHookMethodNormalRouting(
	_In_ PVOID NormalContext, // the info
	_In_ PVOID SystemArgument1, // the flag
	_In_ PVOID SystemArgument2
)
{
	UNREFERENCED_PARAMETER(SystemArgument2);
	_UNCRYPT_INJECT_INFO *info = (_UNCRYPT_INJECT_INFO*)NormalContext;
	ULONG flags = (ULONG)SystemArgument1;
	UNICODE_STRING tmp;
	
	WCHAR buff[128];
	tmp.Buffer = buff;
	tmp.MaximumLength = 128;
	tmp.Length = 0;
	RtlIntegerToUnicodeString(flags, 0, &tmp);
	UncryptApcQueue(
		UserMode,
		(PKNORMAL_ROUTINE)(ULONG_PTR)info->HookAllRoutineAddress,
		&tmp,
		NULL,
		NULL
	);
}
