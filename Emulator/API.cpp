#include "API.h"

void EmuFunc()
{
	api[(TCHAR*)"GetProcAddress"] = EmuGetProcAddress;
}