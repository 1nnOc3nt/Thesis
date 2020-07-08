#include "Emulator.h"

int _tmain(int argc, TCHAR* argv[])
{
	if (argc >= 3 && (strstr(argv[1], "-f") != NULL))
	{
		TCHAR buffer[MAX_PATH] = { 0 };
		start_time = clock();
		AnalyzeFile* emulator = new AnalyzeFile(argv[1], argv[2], argv[3]);
		emulator->StartAnalyze();
		end_time = clock();
		double time_taken = double(end_time - start_time) / double(CLOCKS_PER_SEC);
		_stprintf(buffer, "\n[!] Total execution time: %fs", time_taken);
		UcPrint(buffer);
		delete emulator;
	}
	else if (argc >= 3 && !strcmp(argv[1], "-d"))
	{
		WIN32_FIND_DATA ffd;
		TCHAR szDir[MAX_PATH] = { 0 };
		HANDLE hFind = INVALID_HANDLE_VALUE;
		_stprintf(szDir, "%s\\*", argv[2]);

		hFind = FindFirstFile(szDir, &ffd);

		if (hFind == INVALID_HANDLE_VALUE)
			HandleError();

		do
		{
			if (ffd.dwFileAttributes & 0xff ^ FILE_ATTRIBUTE_DIRECTORY)
			{
				if (!strcmp(PathFindExtension(ffd.cFileName), ".exe"))
				{
					TCHAR cmd[MAX_PATH] = { 0 };
					STARTUPINFO si;
					PROCESS_INFORMATION pi;

					ZeroMemory(&si, sizeof(si));
					si.cb = sizeof(si);
					ZeroMemory(&pi, sizeof(pi));
					_stprintf(cmd, "Emulator.exe -fr %s\\%s", argv[2], ffd.cFileName);
					CreateProcess(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
				}
			}
		} while (FindNextFile(hFind, &ffd) != 0);

		FindClose(hFind);
	}
	else
	{
		_tprintf("[*] Usage: Emulator.exe <options> <Path to executable file> <Argument>\n");
		_tprintf( "    Options:\n");
		_tprintf("           -f: Emulate a file\n");
		_tprintf("               a: Display all instructions\n");
		_tprintf("               r: Display registries\n");
		_tprintf("           -d: Emulate all files in directory\n");
	}
		
	return 0;
}