#include "Capstone.h"
#include <Windows.h>

#include <iostream>
#include <vector>
using std::cout; 
using std::endl;

Capstone::Capstone()
	: Handle(0), err(CS_ERR_OK), pInsn(nullptr), OptMem{}
{

}

Capstone::~Capstone()
{

}

void Capstone::InitCapstone(
)
{
	OptMem.free = free;
	OptMem.calloc = calloc;
	OptMem.malloc = malloc;
	OptMem.realloc = realloc;
	OptMem.vsnprintf = (cs_vsnprintf_t)vsprintf_s;
	cs_option(NULL, CS_OPT_MEM, (size_t)&OptMem);
#ifdef _WIN64
	cs_open(CS_ARCH_X86, CS_MODE_64, &Handle);
#else
	cs_open(CS_ARCH_X86, CS_MODE_32, &Handle);
#endif
}

void Capstone::ShowAssembly(
	uint64_t mapexecripaddr,
	const void* pAddr, 
	size_t nLen
)
{
	if (!Handle || !pAddr || nLen == 0)
		return;

	cs_insn* ins = nullptr;
	std::vector<BYTE> opCode(nLen * 16);

	RtlMoveMemory(opCode.data(), pAddr, opCode.size());

	size_t count = cs_disasm(Handle, opCode.data(), opCode.size(), mapexecripaddr, nLen, &ins);
	if (count == 0 || !ins)
		return;

	for (size_t i = 0; i < count; ++i)
	{
		// printf("%08X\t", ins[i].address);
		printf("0x%I64X\t", ins[i].address);
		for (uint16_t j = 0; j < 16; ++j)
		{
			if (j < ins[i].size)
				printf("%02X", ins[i].bytes[j]);
			else
				printf(" ");
		}
		printf("\t");
		printf("%s  ", ins[i].mnemonic);
		cout << ins[i].op_str << endl;  
	}
	printf("\n");
	cs_free(ins, count);
}

void Capstone::Close(
)
{
	if (Handle)
		cs_close(&Handle);
}
