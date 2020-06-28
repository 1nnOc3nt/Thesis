#include "AnalyzeFile.h"

AnalyzeFile::AnalyzeFile(TCHAR* mode, TCHAR* filePath, TCHAR* arg)
{
	this->mode = mode;
	this->arg = arg;
	this->filePath = filePath;
	loader = new Loader(filePath, arg);
}

/*---------------------------------------------Emulate Code-------------------------------------------*/
int AnalyzeFile::StartAnalyze()
{
	uc_err err;
	TCHAR buffer[MAX_PATH] = { 0 };

	_stprintf(buffer, "<EmuLogs>\n");
	UcPrint(buffer);
	//_stprintf(buffer, "<PEFile filePath=\"%s\" />\n", filePath);
	//UcPrint(buffer);

	if (strstr(mode, "a") != NULL)
		_printAsm = TRUE;
	if (strstr(mode, "r") != NULL)
		_printReg = TRUE;

	//Load PE & setup environment
	if (loader->Load(uc))
		return -1;

	//Hook code
	err = uc_hook_add(uc, &hookcode, UC_HOOK_CODE, hook_code, NULL, 1, 0);
	if (err != UC_ERR_OK)
		HandleUcError(err);

	err = uc_emu_start(uc, loader->getEntryPoint(), 0, 0, 0);
	if (err != UC_ERR_OK)
		HandleUcError(err);


	_stprintf(buffer, "</EmuLogs>\n");
	UcPrint(buffer);
	return 0;
}

AnalyzeFile::~AnalyzeFile()
{
	delete loader;
	uc_close(uc);
}