#include "AnalyzeFile.h"

AnalyzeFile::AnalyzeFile(TCHAR* filePath, TCHAR* arg)
{
	this->arg = arg;
	this->filePath = filePath;
	loader = new Loader(filePath, arg);
}

/*---------------------------------------------Emulate Code-------------------------------------------*/
int AnalyzeFile::StartAnalyze()
{
	uc_err err;
	
	_tprintf("[*] Analyzing: %s\n", filePath);

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


	_tprintf("[*] Done!\n");
	return 0;
}

AnalyzeFile::~AnalyzeFile()
{
	delete loader;
	uc_close(uc);
}