#pragma once
#include <windows.h>
#include <tchar.h>
#include "Manager.h"
#include <stdio.h>
#include <SubAuth.h>


extern "C"
{
	BOOL DllMain(
		HINSTANCE hinstDLL,
		DWORD fdwReason,
		LPVOID lpvReserved
	);
	
}
NTSTATUS WINAPI RtlUnicodeStringToInteger(
	const UNICODE_STRING *str, /* [I] Unicode string to be converted */
	ULONG base,                /* [I] Number base for conversion (allowed 0, 2, 8, 10 or 16) */
	ULONG *value)              /* [O] Destination for the converted value */
{
	LPWSTR lpwstr = str->Buffer;
	USHORT CharsRemaining = str->Length / sizeof(WCHAR);
	WCHAR wchCurrent;
	int digit;
	ULONG RunningTotal = 0;
	BOOL bMinus = FALSE;

	while (CharsRemaining >= 1 && *lpwstr <= ' ') {
		lpwstr++;
		CharsRemaining--;
	} /* while */

	if (CharsRemaining >= 1) {
		if (*lpwstr == '+') {
			lpwstr++;
			CharsRemaining--;
		}
		else if (*lpwstr == '-') {
			bMinus = TRUE;
			lpwstr++;
			CharsRemaining--;
		} /* if */
	} /* if */

	if (base == 0) {
		base = 10;
		if (CharsRemaining >= 2 && lpwstr[0] == '0') {
			if (lpwstr[1] == 'b') {
				lpwstr += 2;
				CharsRemaining -= 2;
				base = 2;
			}
			else if (lpwstr[1] == 'o') {
				lpwstr += 2;
				CharsRemaining -= 2;
				base = 8;
			}
			else if (lpwstr[1] == 'x') {
				lpwstr += 2;
				CharsRemaining -= 2;
				base = 16;
			} /* if */
		} /* if */
	}
	else if (base != 2 && base != 8 && base != 10 && base != 16) {
		return STATUS_INVALID_PARAMETER;
	} /* if */

	if (value == NULL) {
		return STATUS_ACCESS_VIOLATION;
	} /* if */

	while (CharsRemaining >= 1) {
		wchCurrent = *lpwstr;
		if (wchCurrent >= '0' && wchCurrent <= '9') {
			digit = wchCurrent - '0';
		}
		else if (wchCurrent >= 'A' && wchCurrent <= 'Z') {
			digit = wchCurrent - 'A' + 10;
		}
		else if (wchCurrent >= 'a' && wchCurrent <= 'z') {
			digit = wchCurrent - 'a' + 10;
		}
		else {
			digit = -1;
		} /* if */
		if (digit < 0 || digit >= base) {
			*value = bMinus ? -RunningTotal : RunningTotal;
			return STATUS_SUCCESS;
		} /* if */

		RunningTotal = RunningTotal * base + digit;
		lpwstr++;
		CharsRemaining--;
	} /* while */

	*value = bMinus ? -RunningTotal : RunningTotal;
	return STATUS_SUCCESS;
}

