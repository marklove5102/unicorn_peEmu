#include <unicorn/unicorn.h>

#include <cstdio>
#include <iostream>
#include <string>

#include "SimplePeEmu.h"

int wmain(int argc, wchar_t** argv)
{
    std::wstring wSampleName;
    if (argc >= 2)
    {
        wSampleName = argv[1];
    }
    else
    {
        wchar_t bufname[MAX_PATH] = { 0, };
        wprintf(L"please sample path: ");
        if (wscanf_s(L"%259ls", bufname, static_cast<unsigned>(_countof(bufname))) != 1)
            return 0;

        wSampleName = bufname;
    }

    if (wSampleName.empty())
        return 0;

    SimplePeEmu emu;
    if (!emu.Load(wSampleName) || !emu.Run())
    {
        std::cerr << "[emu] " << emu.LastError() << std::endl;
        return 1;
    }

    return 0;
}
