#pragma once
extern "C"
{
	#include <wdm.h>
	#include <ntddk.h>
	#include <ntimage.h>


	typedef
		VOID
		(NTAPI *PKNORMAL_ROUTINE)(
			_In_ PVOID NormalContext,
			_In_ PVOID SystemArgument1,
			_In_ PVOID SystemArgument2
			);

	typedef
		VOID
		(NTAPI *PKKERNEL_ROUTINE)(
			_In_ PKAPC Apc,
			_Inout_ PKNORMAL_ROUTINE* NormalRoutine,
			_Inout_ PVOID* NormalContext,
			_Inout_ PVOID* SystemArgument1,
			_Inout_ PVOID* SystemArgument2
			);

	typedef
		VOID
		(NTAPI *PKRUNDOWN_ROUTINE) (
			_In_ PKAPC Apc
			);
	typedef enum _KAPC_ENVIRONMENT
	{
		OriginalApcEnvironment,
		AttachedApcEnvironment,
		CurrentApcEnvironment,
		InsertApcEnvironment
	} KAPC_ENVIRONMENT;

	NTKERNELAPI
	VOID
	NTAPI
	KeInitializeApc(
		_Out_ PRKAPC Apc,
		_In_ PETHREAD Thread,
		_In_ KAPC_ENVIRONMENT Environment,
		_In_ PKKERNEL_ROUTINE KernelRoutine,
		_In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
		_In_opt_ PKNORMAL_ROUTINE NormalRoutine,
		_In_opt_ KPROCESSOR_MODE ApcMode,
		_In_opt_ PVOID NormalContext
	);

	NTKERNELAPI
	BOOLEAN
	NTAPI
	KeInsertQueueApc(
		_Inout_ PRKAPC Apc,
		_In_opt_ PVOID SystemArgument1,
		_In_opt_ PVOID SystemArgument2,
		_In_ KPRIORITY Increment
	);

	NTSTATUS 
	NTAPI 
	UncryptApcQueue(_In_ KPROCESSOR_MODE ApcMode,
	_In_ PKNORMAL_ROUTINE NormalRoutine,
	_In_ PVOID NormalContext,
	_In_ PVOID SystemArgument1,
	_In_ PVOID SystemArgument2);

	VOID
	NTAPI
	UncryptCallHookMethodNormalRouting(
			_In_ PVOID NormalContext,
			_In_ PVOID SystemArgument1,
			_In_ PVOID SystemArgument2
		);

	VOID
	NTAPI
	UncryptInjectApcNormalRoutine(
		_In_ PVOID NormalContext,
		_In_ PVOID SystemArgument1,
		_In_ PVOID SystemArgument2
	);

	VOID
	NTAPI
	UncryptInjectApcKernelRoutine(
		_In_ PKAPC Apc,
		_Inout_ PKNORMAL_ROUTINE* NormalRoutine,
		_Inout_ PVOID* NormalContext,
		_Inout_ PVOID* SystemArgument1,
		_Inout_ PVOID* SystemArgument2
	);

	NTSTATUS
	NTAPI
	InjectThunkLess(
		_In_ _UNCRYPT_INJECT_INFO *InjectionInfo,
		_In_ HANDLE SectionHandle,
		_In_ SIZE_T SectionSize);
}