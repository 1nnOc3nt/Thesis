#pragma once
#include "Loader.h"
#include "Hook.h"

class AnalyzeFile
{
	private:
		TCHAR* filePath;
		TCHAR* arg;
		uc_engine* uc;
		uc_hook hookcode;
		Loader* loader;
	public:
		AnalyzeFile(TCHAR* filePath, TCHAR* arg);
		int StartAnalyze();
		~AnalyzeFile();
};

