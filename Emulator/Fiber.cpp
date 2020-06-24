#include "Fiber.h"

DWORD _index = 0;
map<DWORD, DWORD>fiber;

DWORD AllocFiber()
{
	fiber[_index] = 0;
	return _index++;
}

DWORD SetFiber(DWORD index, DWORD data)
{
	if (fiber.find(index) != fiber.end())
	{
		fiber[index] = data;
		return 1;
	}
	return 0;
}

DWORD GetFiber(DWORD index)
{
	DWORD data = 0;
	if (fiber.empty())
		return 0;
	else
	{
		if (fiber.find(index) == fiber.end())
			return 0;
		else
			data = fiber[index];
	}
	return data;
}

DWORD FreeFiber(DWORD index)
{
	if (fiber.find(index) != fiber.end())
	{
		fiber.erase(index);
		return 1;
	}
	return 0;
}