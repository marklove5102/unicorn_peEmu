#pragma once
#ifndef _CAPSTONE_H_
#define _CAPSTONE_H_
#include <cstddef>
#include <cstdint>
#include <capstone.h>

class Capstone
{
public:
	Capstone();
	virtual ~Capstone();

public:

	void InitCapstone();
	void ShowAssembly(uint64_t mapexecripaddr, const void* pAddr, size_t nLen);
	void Close();

private:

	csh Handle;
	cs_err err;	
	cs_insn* pInsn; 
	cs_opt_mem OptMem;
};

#endif
