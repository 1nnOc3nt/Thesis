#include "PE.h"

PE::PE(TCHAR* filePath)
{
	this->filePath = filePath;
	pe = NULL;
	arch = 0;
	imageBase = 0;
	entryPoint = 0;
	sizeOfImage = 0;
	importRVA = 0;
	exportRVA = 0;
	memMap = mapPE();
}

LPVOID PE::mapPE()
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwFileSize = 0;
	HANDLE hMapFile = NULL;
	LPVOID lpMapAddress = NULL;

	LPVOID tempMem = NULL;

	PIMAGE_SECTION_HEADER section = NULL;

	/*-------------------------------------------Load file into memory-----------------------------------------*/

	//Open file to map to memory
	hFile = CreateFile(filePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		HandleError();

	//Get file size
	dwFileSize = GetFileSize(hFile, NULL);

	//Create file mapping object
	hMapFile = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, dwFileSize, NULL);
	if (hMapFile == NULL)
		HandleError();

	CloseHandle(hFile);

	//Map view of file
	lpMapAddress = MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, 0);
	if (lpMapAddress == NULL)
		HandleError();

	CloseHandle(hMapFile);

	/*---------------------------------------Map section into temp memory----------------------------------------*/

	//Get PE Header
	pe = PIMAGE_NT_HEADERS(PCHAR(lpMapAddress) + PIMAGE_DOS_HEADER(lpMapAddress)->e_lfanew);

	//Get PE architecture
	arch = pe->FileHeader.Machine;

	//Get Image Base address
	imageBase = pe->OptionalHeader.ImageBase;

	//Get Size Of Image
	sizeOfImage = pe->OptionalHeader.SizeOfImage;

	//Get VA of entry point
	entryPoint = pe->OptionalHeader.ImageBase + pe->OptionalHeader.AddressOfEntryPoint;

	//Get Import RVA
	importRVA = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	//Get Export RVA
	exportRVA = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	//Allocate temp memory
	tempMem = VirtualAlloc(NULL, sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (tempMem == NULL)
		HandleError();

	//Write header into temp memory
	CopyMemory(tempMem, lpMapAddress, pe->OptionalHeader.SizeOfHeaders);

	//Write sections into temp memory
	section = IMAGE_FIRST_SECTION(pe);
	for (ULONG i = 0; i < pe->FileHeader.NumberOfSections; i++)
	{
		CopyMemory(PCHAR(tempMem) + section[i].VirtualAddress,
			PCHAR(lpMapAddress) + section[i].PointerToRawData,
			section[i].SizeOfRawData);
	}

	UnmapViewOfFile(lpMapAddress);

	return tempMem;
}

DWORD PE::getArch() const
{
	return arch;
}

DWORD PE::getImageBase() const
{
	return imageBase;
}

DWORD PE::getEntryPoint() const
{
	return entryPoint;
}

DWORD PE::getSizeOfImage() const
{
	return sizeOfImage;
}

DWORD PE::getImportRVA() const
{
	return importRVA;
}

DWORD PE::getExportRVA() const
{
	return exportRVA;
}

LPVOID PE::getData() const
{
	return memMap;
}

BOOL PE::isDll() const
{
	return (pe->FileHeader.Characteristics >= IMAGE_FILE_DLL);
}

PE::~PE()
{
	VirtualFree(memMap, sizeOfImage, MEM_RELEASE);
}