#pragma once
extern "C"
{
	#include <ntddk.h>
	VOID ProcessNotifyHook(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
	VOID ImageNotifyHook(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);
}