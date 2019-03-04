#include "DllMain.h"

BOOL DllMain(
	HINSTANCE hinstDLL,
	DWORD fdwReason,
	LPVOID lpvReserved
)
{
	switch (fdwReason)
	{
		case DLL_PROCESS_ATTACH:
		{
			//Init the DLL - for now the hooker and the logger.
			
			break;
		}
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
		{
			//Remove all - hooker and logger.
			break;
		}
	}
	return TRUE;
}
extern "C" VOID _declspec(dllexport) HookFunctions(PUNICODE_STRING flag)
{
	ULONG value;
	RtlUnicodeStringToInteger(flag, 0, &value);

}
