#pragma once
#include <windows.h>
#include <string.h>
#define DRIVER_FUNC_INSTALL     0x01
#define DRIVER_FUNC_REMOVE      0x02

#define DRIVER_NAME             "UncryptorInjector"


BOOLEAN
ManageDriver(
	_In_ LPCTSTR  DriverName,
	_In_ LPCTSTR  ServiceName,
	_In_ USHORT   Function
);

BOOLEAN
SetupDriverName(
	_Inout_updates_bytes_all_(BufferLength) PTCHAR DriverLocation,
	_In_ ULONG BufferLength
);
