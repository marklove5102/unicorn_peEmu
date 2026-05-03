#include "mem.h"

#include <Windows.h>
#include <list>
std::list<LPVOID> g_MemList;

void* ExAllocMemory(size_t len)
{
	if (len)
	{
		auto m_pBuffer = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (m_pBuffer)
			g_MemList.push_back(m_pBuffer);
		else
			return NULL;
		return m_pBuffer;
	}
	return NULL;
}

void* ExAllocHeap(size_t len)
{
	if (!len)
		return NULL;
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len);
}
