#include "Emulator.h"

int _tmain(int argc, TCHAR* argv[])
{
	if (argc >= 3 && !strcmp(argv[1], "-f"))
	{
		AnalyzeFile* emulator = new AnalyzeFile(argv[2], argv[3]);
		emulator->StartAnalyze();
		delete emulator;
	}
	else
		_tprintf("[*] Usage: Emulator.exe -f <Path to executable file> <Arguments>\n");
	return 0;
}