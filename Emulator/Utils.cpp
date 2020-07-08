#include "Utils.h"

void UcPrintAPIArg(TCHAR buffer[], DWORD tab)
{
	WriteFile(_outFile, buffer, strlen(buffer), &_dwBytesWritten, NULL);
	ZeroMemory(buffer, MAX_PATH); 
}

DWORD getEAX(uc_engine* uc)
{
	uc_err err;
	DWORD eax = 0;
	err = uc_reg_read(uc, UC_X86_REG_EAX, &eax);
	if (err != UC_ERR_OK)
		HandleUcErrorDWORD(err);
	return eax;
}

DWORD getEBX(uc_engine* uc)
{
	uc_err err;
	DWORD ebx = 0;
	err = uc_reg_read(uc, UC_X86_REG_EBX, &ebx);
	if (err != UC_ERR_OK)
		HandleUcErrorDWORD(err);
	return ebx;
}

DWORD getECX(uc_engine* uc)
{
	uc_err err;
	DWORD ecx = 0;
	err = uc_reg_read(uc, UC_X86_REG_ECX, &ecx);
	if (err != UC_ERR_OK)
		HandleUcErrorDWORD(err);
	return ecx;
}

DWORD getEDX(uc_engine* uc)
{
	uc_err err;
	DWORD edx = 0;
	err = uc_reg_read(uc, UC_X86_REG_EDX, &edx);
	if (err != UC_ERR_OK)
		HandleUcErrorDWORD(err);
	return edx;
}

DWORD getESP(uc_engine* uc)
{
	uc_err err;
	DWORD esp = 0;
	err = uc_reg_read(uc, UC_X86_REG_ESP, &esp);
	if (err != UC_ERR_OK)
		HandleUcErrorDWORD(err);
	return esp;
}


DWORD getEBP(uc_engine* uc)
{
	uc_err err;
	DWORD ebp = 0;
	err = uc_reg_read(uc, UC_X86_REG_EBP, &ebp);
	if (err != UC_ERR_OK)
		HandleUcErrorDWORD(err);
	return ebp;
}

DWORD getESI(uc_engine* uc)
{
	uc_err err;
	DWORD esi = 0;
	err = uc_reg_read(uc, UC_X86_REG_ESI, &esi);
	if (err != UC_ERR_OK)
		HandleUcErrorDWORD(err);
	return esi;
}

DWORD getEDI(uc_engine* uc)
{
	uc_err err;
	DWORD edi = 0;
	err = uc_reg_read(uc, UC_X86_REG_EDI, &edi);
	if (err != UC_ERR_OK)
		HandleUcErrorDWORD(err);
	return edi;
}

void getRegistries(uc_engine* uc, DWORD tab)
{	
	TCHAR regString[MAX_PATH] = { 0 };
	TCHAR regStringW[MAX_PATH] = { 0 };
	TCHAR buffer[MAX_PATH] = { 0 };

	char total_tab[100] = { 0 };
	memset(total_tab, '\t', tab);

	WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
	WriteFile(_outFile, "<Registries>\n", strlen("<Registries>\n"), &_dwBytesWritten, NULL);

	DWORD eax = getEAX(uc);
	getString(uc, eax, regString);
	getStringW(uc, eax, regStringW);

	if ((strcmp(regString, "") != 0 ) && strlen(regString) >= 2)
	{
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t<eax value=0x%lX>\n", eax);
		UcPrint(buffer);
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t\t<string value=\"%s\" />\n", regString);
		UcPrint(buffer);
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t</eax>\n");
		UcPrint(buffer);
	}
	else if (strcmp(regStringW, ""))
	{
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t<eax value=0x%lX>\n", eax);
		UcPrint(buffer);
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t\t<string value=\"%s\" />\n", regStringW);
		UcPrint(buffer);
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t</eax>\n");
		UcPrint(buffer);
	}
	else
	{
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t<eax value=0x%lX />\n", eax);
		UcPrint(buffer);
	}
	memset(regString, 0, MAX_PATH);
	memset(regStringW, 0, MAX_PATH);

	DWORD ebx = getEBX(uc);
	getString(uc, ebx, regString);
	getStringW(uc, ebx, regStringW);

	if ((strcmp(regString, "") != 0) && strlen(regString) >= 2)
	{
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t<ebx value=0x%lX>\n", ebx);
		UcPrint(buffer);
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t\t<string value=\"%s\" />\n", regString);
		UcPrint(buffer);
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t</ebx>\n");
		UcPrint(buffer);
	}
	else if (strcmp(regStringW, ""))
	{
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t<ebx value=0x%lX>\n", ebx);
		UcPrint(buffer);
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t\t<string value=\"%s\" />\n", regStringW);
		UcPrint(buffer);
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t</ebx>\n");
		UcPrint(buffer);
	}
	else
	{
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t<ebx value=0x%lX />\n", ebx);
		UcPrint(buffer);
	}
	memset(regString, 0, MAX_PATH);
	memset(regStringW, 0, MAX_PATH);

	DWORD ecx = getECX(uc);
	getString(uc, ecx, regString);
	getStringW(uc, ecx, regStringW);

	if ((strcmp(regString, "") != 0) && strlen(regString) >= 2)
	{
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t<ecx value=0x%lX>\n", ecx);
		UcPrint(buffer);
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t\t<string value=\"%s\" />\n", regString);
		UcPrint(buffer);
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t</ecx>\n");
		UcPrint(buffer);
	}
	else if (strcmp(regStringW, ""))
	{
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t<ecx value=0x%lX>\n", ecx);
		UcPrint(buffer);
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t\t<string value=\"%s\" />\n", regStringW);
		UcPrint(buffer);
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t</ecx>\n");
		UcPrint(buffer);
	}
	else
	{
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t<ecx value=0x%lX />\n", ecx);
		UcPrint(buffer);
	}
	memset(regString, 0, MAX_PATH);
	memset(regStringW, 0, MAX_PATH);

	DWORD edx = getEDX(uc);
	getString(uc, edx, regString);
	getStringW(uc, edx, regStringW);
	if ((strcmp(regString, "") != 0) && strlen(regString) >= 2)
	{
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t<edx value=0x%lX>\n", edx);
		UcPrint(buffer);
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t\t<string value=\"%s\" />\n", regString);
		UcPrint(buffer);
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t</edx>\n");
		UcPrint(buffer);
	}
	else if (strcmp(regStringW, ""))
	{
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t<edx value=0x%lX>\n", edx);
		UcPrint(buffer);
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t\t<string value=\"%s\" />\n", regStringW);
		UcPrint(buffer);
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t</edx>\n");
		UcPrint(buffer);
	}
	else
	{
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t<edx value=0x%lX />\n", edx);
		UcPrint(buffer);
	}
	memset(regString, 0, MAX_PATH);
	memset(regStringW, 0, MAX_PATH);

	DWORD esp = getESP(uc);
	getString(uc, esp, regString);
	getStringW(uc, esp, regStringW);

	if ((strcmp(regString, "") != 0) && strlen(regString) >= 2)
	{
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t<esp value=0x%lX>\n", esp);
		UcPrint(buffer);
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t\t<string value=\"%s\" />\n", regString);
		UcPrint(buffer);
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t</esp>\n");
		UcPrint(buffer);
	}
	else if (strcmp(regStringW, ""))
	{
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t<esp value=0x%lX>\n", esp);
		UcPrint(buffer);
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t\t<string value=\"%s\" />\n", regStringW);
		UcPrint(buffer);
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t</esp>\n");
		UcPrint(buffer);
	}
	else
	{
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t<esp value=0x%lX />\n", esp);
		UcPrint(buffer);
	}
	memset(regString, 0, MAX_PATH);
	memset(regStringW, 0, MAX_PATH);


	DWORD ebp = getEBP(uc);
	getString(uc, ebp, regString);
	getStringW(uc, ebp, regStringW);

	if ((strcmp(regString, "") != 0) && strlen(regString) >= 2)
	{
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t<ebp value=0x%lX>\n", ebp);
		UcPrint(buffer);
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t\t<string value=\"%s\" />\n", regString);
		UcPrint(buffer);
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t</ebp>\n");
		UcPrint(buffer);
	}
	else if (strcmp(regStringW, ""))
	{
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t<ebp value=0x%lX>\n", ebp);
		UcPrint(buffer);
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t\t<string value=\"%s\" />\n", regStringW);
		UcPrint(buffer);
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t</ebp>\n");
		UcPrint(buffer);
	}
	else
	{
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t<ebp value=0x%lX />\n", ebp);
		UcPrint(buffer);
	}
	memset(regString, 0, MAX_PATH);
	memset(regStringW, 0, MAX_PATH);

	DWORD esi = getESI(uc);
	getString(uc, esi, regString);
	getStringW(uc, esi, regStringW);

	if ((strcmp(regString, "") != 0) && strlen(regString) >= 2)
	{
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t<esi value=0x%lX>\n", esi);
		UcPrint(buffer);
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t\t<string value=\"%s\" />\n", regString);
		UcPrint(buffer);
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t</esi>\n");
		UcPrint(buffer);
	}
	else if (strcmp(regStringW, ""))
	{
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t<esi value=0x%lX>\n", esi);
		UcPrint(buffer);
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t\t<string value=\"%s\" />\n", regStringW);
		UcPrint(buffer);
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t</esi>\n");
		UcPrint(buffer);
	}
	else
	{
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t<esi value=0x%lX />\n", esi);
		UcPrint(buffer);
	}
	memset(regString, 0, MAX_PATH);
	memset(regStringW, 0, MAX_PATH);

	DWORD edi = getEDI(uc);
	getString(uc, edi, regString);
	getStringW(uc, edi, regStringW);
	if ((strcmp(regString, "") != 0) && strlen(regString) >= 2)
	{
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t<edi value=0x%lX>\n", edi);
		UcPrint(buffer);
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t\t<string value=\"%s\" />\n", regString);
		UcPrint(buffer);
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t</edi>\n");
		UcPrint(buffer);
	}
	else if (strcmp(regStringW, ""))
	{
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t<edi value=0x%lX>\n", edi);
		UcPrint(buffer);
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t\t<string value=\"%s\" />\n", regStringW);
		UcPrint(buffer);
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t</edi>\n");
		UcPrint(buffer);
	}
	else
	{
		WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
		_stprintf(buffer, "\t<edi value=0x%lX />\n", edi);
		UcPrint(buffer);
	}
	memset(regString, 0, MAX_PATH);
	memset(regStringW, 0, MAX_PATH);

	WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
	WriteFile(_outFile, "</Registries>\n", strlen("</Registries>\n"), &_dwBytesWritten, NULL);
}

void CleanupStack(uc_engine* uc, DWORD number)
{
	uc_err err;
	DWORD sp = 0;
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += (0x4 * number);

	err = uc_reg_write(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);
}

void getString(uc_engine* uc, DWORD address, TCHAR cString[])
{
	uc_err err;
	TCHAR character = 0;
	DWORD count = 0;

	while (TRUE)
	{
		err = uc_mem_read(uc, address, &character, 1);
		if (err != UC_ERR_OK)
		{
			memset(cString, 0, MAX_PATH);
			return;
		}

		if (character == 0 || character == 10 || character == 13)
			break;
		else if (character < 32 || character >= 127)
		{
			memset(cString, 0, MAX_PATH);
			return;
		}

		if (count >= MAX_PATH)
			break;

		strncat(cString, &character, 1);
		address++;
		count++;
	}
}

void getStringW(uc_engine* uc, DWORD address, TCHAR cString[])
{
	uc_err err;
	TCHAR character = 0;
	TCHAR characterNull = 0;
	DWORD count = 0;

	while (TRUE)
	{
		err = uc_mem_read(uc, address, &character, 1);
		if (err != UC_ERR_OK)
		{
			memset(cString, 0, MAX_PATH);
			return;
		}

		err = uc_mem_read(uc, address+1, &characterNull, 1);
		if (err != UC_ERR_OK)
		{
			memset(cString, 0, MAX_PATH);
			return;
		}

		if ((character == 0 && characterNull == 0) || (character == 10 && characterNull == 0) || character == 13 && characterNull == 0)
			break;
		else if (character < 32 || character >= 127 || characterNull != 0)
		{
			memset(cString, 0, MAX_PATH);
			return;
		}

		if (count >= MAX_PATH)
			break;

		strncat(cString, &character, 1);
		address += 2;
		count++;
	}
}

DWORD getDWORD(uc_engine* uc, DWORD address)
{
	uc_err err;
	DWORD number = 0;
	err = uc_mem_read(uc, address, &number, sizeof(DWORD));
	if (err != UC_ERR_OK)
		return 0;
	return number;
}

void getStack(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD sp = 0;
	char total_tab[100] = { 0 };
	memset(total_tab, '\t', tab);

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
	WriteFile(_outFile, "<Stack>\n", strlen("<Stack>\n"), &_dwBytesWritten, NULL);

	for (size_t i = 0; i < 5; i++)
	{
		TCHAR stackValueString[MAX_PATH] = { 0 };
		TCHAR stackValueStringW[MAX_PATH] = { 0 };
		DWORD stackValue = 0;
		DWORD dwStackValue = 0;
		TCHAR buffer[MAX_PATH] = { 0 };
		
		stackValue = getDWORD(uc, sp);

		if (stackValue != 0)
		{
			dwStackValue = getDWORD(uc, stackValue);
			getString(uc, stackValue, stackValueString);
			getStringW(uc, stackValue, stackValueStringW);
		}

		if (strcmp(stackValueString, "") && strlen(stackValueString) >= 2)
		{
			WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
			_stprintf(buffer, "\t<argument index=%d value=0x%lX>\n", i + 1, stackValue);
			UcPrint(buffer);
			WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
			_stprintf(buffer, "\t\t<string value=\"%s\" />\n", stackValueString);
			UcPrint(buffer);
			WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
			_stprintf(buffer, "\t</argument>\n");
			UcPrint(buffer);
		}
		else if (strcmp(stackValueStringW, ""))
		{
			WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
			_stprintf(buffer, "\t<argument index=%d value=0x%lX>\n", i + 1, stackValue);
			UcPrint(buffer);
			WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
			_stprintf(buffer, "\t\t<dword value=0x%lX>\n", dwStackValue);
			UcPrint(buffer);
			WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
			_stprintf(buffer, "\t\t\t<string value=\"%s\" />\n", stackValueStringW);
			UcPrint(buffer);
			WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
			_stprintf(buffer, "\t\t<dword>\n");
			UcPrint(buffer);
			WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
			_stprintf(buffer, "\t</argument>\n");
			UcPrint(buffer);
		}
		else if (dwStackValue != 0)
		{
			getString(uc, dwStackValue, stackValueString);
			getStringW(uc, dwStackValue, stackValueStringW);
			if (strcmp(stackValueString, "") && strlen(stackValueString) >= 2)
			{
				WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
				_stprintf(buffer, "\t<argument index=%d value=0x%lX>\n", i + 1, stackValue);
				UcPrint(buffer);
				WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
				_stprintf(buffer, "\t\t<dword value=0x%lX>\n", dwStackValue);
				UcPrint(buffer);
				WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
				_stprintf(buffer, "\t\t\t<string value=\"%s\" />\n", stackValueString);
				UcPrint(buffer);
				WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
				_stprintf(buffer, "\t\t<dword>\n");
				UcPrint(buffer);
				WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
				_stprintf(buffer, "\t</argument>\n");
				UcPrint(buffer);
			}
			else if (strcmp(stackValueStringW, ""))
			{
				WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
				_stprintf(buffer, "\t<argument index=%d value=0x%lX>\n", i + 1, stackValue);
				UcPrint(buffer);
				WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
				_stprintf(buffer, "\t\t<dword value=0x%lX>\n", dwStackValue);
				UcPrint(buffer);
				WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
				_stprintf(buffer, "\t\t\t<string value=\"%s\" />\n", stackValueStringW);
				UcPrint(buffer);
				WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
				_stprintf(buffer, "\t\t<dword>\n");
				UcPrint(buffer);
				WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
				_stprintf(buffer, "\t</argument>\n");
				UcPrint(buffer);
			}
			else
			{
				WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
				_stprintf(buffer, "\t<argument index=%d value=0x%lX>\n", i + 1, stackValue);
				UcPrint(buffer);
				WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
				_stprintf(buffer, "\t\t<dword value=0x%lX />\n", dwStackValue);
				UcPrint(buffer);
				WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
				_stprintf(buffer, "\t</argument>\n");
				UcPrint(buffer);
			}
		}
		else
		{
			WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
			_stprintf(buffer, "\t<argument index=%d value=0x%lX />\n", i + 1, stackValue);
			UcPrint(buffer);
		}
		
		sp += 4;
	}
	WriteFile(_outFile, total_tab, tab, &_dwBytesWritten, NULL);
	WriteFile(_outFile, "</Stack>\n", strlen("</Stack>\n"), &_dwBytesWritten, NULL);
}

void getGeneric(TCHAR genericAccess[], DWORD dwDesiredAccess)
{
	switch (dwDesiredAccess)
	{
	case 0x80000000:
		strcat(genericAccess, "GENERIC_READ");
		break;
	case 0x40000000:
		strcat(genericAccess, "GENERIC_WRITE");
		break;
	case 0x20000000:
		strcat(genericAccess, "GENERIC_EXECUTE");
		break;
	case 0x10000000:
		strcat(genericAccess, "GENERIC_ALL");
		break;
	case 0xC0000000:
		strcat(genericAccess, "GENERIC_READ | GENERIC_WRITE");
		break;
	case 0xA0000000:
		strcat(genericAccess, "GENERIC_READ | GENERIC_EXECUTE");
		break;
	case 0x60000000:
		strcat(genericAccess, "GENERIC_WRITE | GENERIC_EXECUTE");
		break;
	case 0xE0000000:
		strcat(genericAccess, "GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE");
		break;
	default:
		_stprintf(genericAccess, "0x%lX", dwDesiredAccess);
		break;
	}
}

void getShareMode(TCHAR shareMode[], DWORD dwShareMode)
{
	switch (dwShareMode)
	{
	case 0x0:
		strcat(shareMode, "0x0");
		break;
	case 0x4:
		strcat(shareMode, "FILE_SHARE_DELETE");
		break;
	case 0x1:
		strcat(shareMode, "FILE_SHARE_READ");
		break;
	case 0x2:
		strcat(shareMode, "FILE_SHARE_WRITE");
		break;
	case 0x5:
		strcat(shareMode, "FILE_SHARE_DELETE | FILE_SHARE_READ");
		break;
	case 0x6:
		strcat(shareMode, "FILE_SHARE_DELETE | FILE_SHARE_WRITE");
		break;
	case 0x3:
		strcat(shareMode, "FILE_SHARE_READ | FILE_SHARE_WRITE");
		break;
	case 0x7:
		strcat(shareMode, "FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE");
		break;
	default:
		_stprintf(shareMode, "0x%lX", dwShareMode);
		break;
	}
}

void getCreateType(TCHAR createType[], DWORD dwCreationDisposition)
{
	switch (dwCreationDisposition)
	{
	case 0x2:
		strcat(createType, "CREATE_ALWAYS");
		break;
	case 0x1:
		strcat(createType, "CREATE_NEW");
		break;
	case 0x4:
		strcat(createType, "OPEN_ALWAYS");
		break;
	case 0x3:
		strcat(createType, "OPEN_EXISTING");
		break;
	case 0x5:
		strcat(createType, "TRUNCATE_EXISTING");
		break;
	default:
		_stprintf(createType, "0x%lX", dwCreationDisposition);
		break;
	}
}

void getAttribute(TCHAR attribute[], DWORD dwFlagsAndAttributes)
{
	switch (dwFlagsAndAttributes)
	{
	case 0x20:
		strcat(attribute, "FILE_ATTRIBUTE_ARCHIVE");
		break;
	case 0x4000:
		strcat(attribute, "FILE_ATTRIBUTE_ENCRYPTED");
		break;
	case 0x2:
		strcat(attribute, "FILE_ATTRIBUTE_HIDDEN");
		break;
	case 0x80:
		strcat(attribute, "FILE_ATTRIBUTE_NORMAL");
		break;
	case 0x1000:
		strcat(attribute, "FILE_ATTRIBUTE_OFFLINE");
	case 0x1:
		strcat(attribute, "FILE_ATTRIBUTE_OFFLINE");
		break;
	case 0x4:
		strcat(attribute, "FILE_ATTRIBUTE_SYSTEM");
		break;
	case 0x6:
		strcat(attribute, "FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM");
		break;
	case 0x82:
		strcat(attribute, "FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NORMAL");
		break;
	default:
		_stprintf(attribute, "0x%lX", dwFlagsAndAttributes);
		break;
	}
}

void getMappingAttribute(TCHAR attribute[], DWORD lpFileMappingAttributes)
{
	switch (lpFileMappingAttributes)
	{
	case 0xF001F:
		strcat(attribute, "FILE_MAP_ALL_ACCESS");
		break;
	case 0x8:
		strcat(attribute, "FILE_MAP_EXECUTE");
		break;
	case 0x4:
		strcat(attribute, "FILE_MAP_READ");
		break;
	case 0x2:
		strcat(attribute, "FILE_MAP_WRITE");
		break;
	case 0x1:
		strcat(attribute, "FILE_MAP_COPY");
		break;
	case 0x6:
		strcat(attribute, "FILE_MAP_READ | FILE_MAP_WRITE");
		break;
	case 0xC:
		strcat(attribute, "FILE_MAP_READ | FILE_MAP_EXECUTE");
		break;
	case 0xA:
		strcat(attribute, "FILE_MAP_WRITE | FILE_MAP_EXECUTE");
		break;
	case 0xE:
		strcat(attribute, "FILE_MAP_READ | FILE_MAP_WRITE | FILE_MAP_WRITE");
		break;
	case 0x80000000:
		strcat(attribute, "FILE_MAP_RESERVE");
		break;
	case 0x20000000:
		strcat(attribute, "FILE_MAP_LARGE_PAGES");
		break;
	default:
		_stprintf(attribute, "0x%lX", lpFileMappingAttributes);
		break;
	}
}

void getPageAccess(TCHAR pageAccess[], DWORD flProtect)
{
	switch (flProtect)
	{
	case 0x1:
		strcat(pageAccess, "PAGE_NOACCESS");
		break;
	case 0x2:
		strcat(pageAccess, "PAGE_READONLY");
		break;
	case 0x4:
		strcat(pageAccess, "PAGE_READWRITE");
		break;
	case 0x8:
		strcat(pageAccess, "PAGE_WRITECOPY");
		break;
	case 0x10:
		strcat(pageAccess, "PAGE_EXECUTE");
		break;
	case 0x20:
		strcat(pageAccess, "PAGE_EXECUTE_READ");
		break;
	case 0x40:
		strcat(pageAccess, "PAGE_EXECUTE_READWRITE");
		break;
	case 0x80:
		strcat(pageAccess, "PAGE_EXECUTE_WRITECOPY");
		break;
	default:
		_stprintf(pageAccess, "0x%lX", flProtect);
		break;
	}
}

void getMutexAccess(TCHAR mutexAccess[], DWORD dwDesiredAccess)
{
	switch (dwDesiredAccess)
	{
	case 0x1F0001:
		strcat(mutexAccess, "MUTEX_ALL_ACCESS");
		break;
	case 0x1:
		strcat(mutexAccess, "MUTEX_MODIFY_STATE");
		break;
	default:
		_stprintf(mutexAccess, "0x%lX", dwDesiredAccess);
		break;
	}
}

void getCreationFlag(TCHAR creationFlags[], DWORD dwCreationFlags)
{
	switch (dwCreationFlags)
	{
	case 0x10:
		strcat(creationFlags, "CREATE_NEW_CONSOLE");
		break;
	case 0x8000000:
		strcat(creationFlags, "CREATE_NO_WINDOW");
		break;
	case 0x4:
		strcat(creationFlags, "CREATE_SUSPENDED");
		break;
	default:
		_stprintf(creationFlags, "0x%lX", dwCreationFlags);
		break;
	}
}