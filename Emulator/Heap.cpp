#include "Heap.h"

map<DWORD, DWORD>heap;
DWORD _heapAddr = 0;
DWORD _heapSize = 0;

BOOL IsMapped(uc_engine* uc, DWORD heapAddress, DWORD heapSize)
{
	uc_err err;
	uc_mem_region** region = NULL;
	uint32_t count = 0;
	BOOL isMapped = TRUE;

	err = uc_mem_regions(uc, region, &count);
	
	for (int i = 0; i < count; i++)
	{
		if (heapAddress >= region[i]->begin && (heapAddress + heapSize - 1) <= region[i]->end)
			return TRUE;
	}
	return FALSE;
}

DWORD NewHeap(uc_engine* uc, DWORD heapSize)
{
	uc_err err;
	DWORD heapAddress = 0;

	if (heap.empty())
	{
		heapAddress = _heapAddr;
		heap[heapAddress] = heapSize;
	}
	else
	{
		map<DWORD, DWORD>::iterator iterate1;
		map<DWORD, DWORD>::iterator iterate2;

		iterate1 = heap.begin();
		iterate2 = ++heap.begin();
		
		if (heap.size() == 1)
		{
			heapAddress = iterate1->first + iterate1->second;
			heap[heapAddress] = heapSize;
		}
		else
		{
			while (iterate2 != heap.end())
			{
				if ((iterate2->first - (iterate1->first + iterate1->second)) >= heapSize)
				{
					heapAddress = iterate1->first + iterate1->second;
					heap[heapAddress] = heapSize;
					break;
				}
				iterate1++;
				iterate2++;
			}
			if (heapAddress == 0)
			{
				if ((iterate1->first + iterate1->second + heapSize) <= _heapSize)
				{
					heapAddress = iterate1->first + iterate1->second;
					heap[heapAddress] = heapSize;
				}
			}
		}
	}

	if (heapAddress != 0)
	{
		err = uc_mem_map(uc, heapAddress, heapSize, UC_PROT_ALL);
		if (err != UC_ERR_OK)
			HandleUcErrorDWORD(err);
	}

	return heapAddress;
}

DWORD NewHeap(uc_engine* uc, DWORD heapAddress, DWORD heapSize)
{
	uc_err err;

	if (heap.find(heapAddress) == heap.end())
	{
		if (IsMapped(uc, heapAddress, heapSize))
			return 0;
		else
		{
			err = uc_mem_map(uc, heapAddress, heapSize, UC_PROT_ALL);
			if (err != UC_ERR_OK)
				HandleUcErrorDWORD(err);
		}
	}
	return heapAddress;
}

void DeleteHeap(uc_engine* uc, DWORD heapAddress, DWORD heapSize)
{
	uc_err err;
	TCHAR buffer[MAX_PATH] = { 0 };

	if (heap.find(heapAddress) == heap.end())
	{
		_stprintf(buffer, "[!] Error: Given address is not in Heap!\n");
		UcPrint(buffer);
	}
	else
	{
		if (heapSize == heap[heapAddress])
		{
			heap.erase(heapAddress);
			err = uc_mem_unmap(uc, heapAddress, heap[heapAddress]);
			if (err != UC_ERR_OK)
				HandleUcErrorVoid(err);
		}
		else
		{
			DWORD newHeapAddress = heapAddress + heapSize;
			DWORD newHeapSize = heap[heapAddress] - heapSize;
			heap.erase(heapAddress);
			heap[newHeapAddress] = newHeapSize;
			err = uc_mem_unmap(uc, heapAddress, heapSize);
			if (err != UC_ERR_OK)
				HandleUcErrorVoid(err);
		}
	}
}