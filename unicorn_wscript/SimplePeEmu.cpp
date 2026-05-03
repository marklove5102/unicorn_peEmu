#include "SimplePeEmu.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <iostream>

namespace
{
    uint64_t AlignUp(uint64_t value, uint64_t align)
    {
        return (value + align - 1) & ~(align - 1);
    }

    std::string ToLower(std::string value)
    {
        std::transform(value.begin(), value.end(), value.begin(),
            [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        return value;
    }

    uint32_t GuessX86StackBytes(const std::string& apiName)
    {
        const std::string api = ToLower(apiName);
        if (api == "getstdhandle" || api == "exitprocess")
            return 4;
        if (api == "writefile")
            return 20;
        return 0;
    }
}

SimplePeEmu::SimplePeEmu()
    : m_uc(nullptr),
      m_codeHook(0),
      m_invalidHook(0),
      m_is64(false),
      m_machine(0),
      m_imageBase(0),
      m_imageEnd(0),
      m_sizeOfImage(0),
      m_sizeOfHeaders(0),
      m_entryRva(0),
      m_importRva(0),
      m_importSize(0),
      m_stackBase(0),
      m_stackSize(0x100000),
      m_fakeBase(0),
      m_fakeSize(0x10000),
      m_nextFake(0)
{
}

SimplePeEmu::~SimplePeEmu()
{
    if (m_uc)
        uc_close(m_uc);
}

bool SimplePeEmu::Load(const std::wstring& path)
{
    m_path = path;
    return ReadFileToBuffer(path) &&
        ParseHeaders() &&
        BuildImage() &&
        ResolveImports() &&
        OpenEngine() &&
        MapImageAndStack() &&
        InstallHooks();
}

bool SimplePeEmu::Run()
{
    if (!m_uc)
    {
        SetError("emulator is not initialized");
        return false;
    }

    const uint64_t entry = m_imageBase + m_entryRva;
    const uc_err err = uc_emu_start(m_uc, entry, 0, 0, 1000000);
    if (err != UC_ERR_OK)
    {
        SetError(std::string("uc_emu_start failed: ") + uc_strerror(err));
        return false;
    }

    return true;
}

bool SimplePeEmu::ReadFileToBuffer(const std::wstring& path)
{
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
    {
        SetError("failed to open input PE");
        return false;
    }

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > 64 * 1024 * 1024)
    {
        CloseHandle(file);
        SetError("invalid input PE size");
        return false;
    }

    m_file.resize(static_cast<size_t>(size.QuadPart));
    DWORD readBytes = 0;
    const BOOL ok = ReadFile(file, m_file.data(), static_cast<DWORD>(m_file.size()), &readBytes, nullptr);
    CloseHandle(file);

    if (!ok || readBytes != m_file.size())
    {
        SetError("failed to read input PE");
        return false;
    }

    return true;
}

bool SimplePeEmu::ParseHeaders()
{
    if (m_file.size() < sizeof(IMAGE_DOS_HEADER))
    {
        SetError("file is too small for DOS header");
        return false;
    }

    const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(m_file.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
    {
        SetError("invalid DOS header");
        return false;
    }

    if (static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > m_file.size())
    {
        SetError("file is too small for NT header");
        return false;
    }

    const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(m_file.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
    {
        SetError("invalid NT header");
        return false;
    }

    m_machine = nt->FileHeader.Machine;
    m_is64 = nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    if (m_machine != IMAGE_FILE_MACHINE_I386 && m_machine != IMAGE_FILE_MACHINE_AMD64)
    {
        SetError("only x86/x64 PE files are supported");
        return false;
    }

    if (m_is64)
    {
        const auto nt64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(nt);
        m_imageBase = nt64->OptionalHeader.ImageBase;
        m_sizeOfImage = nt64->OptionalHeader.SizeOfImage;
        m_sizeOfHeaders = nt64->OptionalHeader.SizeOfHeaders;
        m_entryRva = nt64->OptionalHeader.AddressOfEntryPoint;
        m_importRva = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        m_importSize = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    }
    else
    {
        const auto nt32 = reinterpret_cast<const IMAGE_NT_HEADERS32*>(nt);
        m_imageBase = nt32->OptionalHeader.ImageBase;
        m_sizeOfImage = nt32->OptionalHeader.SizeOfImage;
        m_sizeOfHeaders = nt32->OptionalHeader.SizeOfHeaders;
        m_entryRva = nt32->OptionalHeader.AddressOfEntryPoint;
        m_importRva = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        m_importSize = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    }

    if (m_sizeOfImage == 0 || m_entryRva >= m_sizeOfImage)
    {
        SetError("invalid image layout");
        return false;
    }

    return true;
}

bool SimplePeEmu::BuildImage()
{
    const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(m_file.data());
    const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(m_file.data() + dos->e_lfanew);
    const auto section = IMAGE_FIRST_SECTION(nt);

    m_image.assign(m_sizeOfImage, 0);
    memcpy(m_image.data(), m_file.data(), std::min<size_t>(m_sizeOfHeaders, m_file.size()));

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
    {
        const auto& s = section[i];
        if (s.VirtualAddress >= m_sizeOfImage || s.PointerToRawData >= m_file.size())
            continue;

        const size_t copySize = std::min<size_t>(s.SizeOfRawData, m_file.size() - s.PointerToRawData);
        if (s.VirtualAddress + copySize > m_image.size())
            continue;

        memcpy(m_image.data() + s.VirtualAddress, m_file.data() + s.PointerToRawData, copySize);
    }

    m_imageEnd = m_imageBase + AlignUp(m_sizeOfImage, 0x1000);
    return true;
}

bool SimplePeEmu::ResolveImports()
{
    if (m_importRva == 0)
        return true;

    auto importDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(RvaPtr(m_importRva));
    if (!importDesc)
    {
        SetError("invalid import directory");
        return false;
    }

    while (importDesc->Name)
    {
        const char* dll = reinterpret_cast<const char*>(RvaPtr(importDesc->Name));
        if (!dll)
        {
            SetError("invalid import DLL name");
            return false;
        }

        const uint64_t thunkRva = importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk;
        uint64_t thunk = thunkRva;
        uint64_t iat = importDesc->FirstThunk;

        while (true)
        {
            uint64_t thunkValue = 0;
            if (m_is64)
                thunkValue = *reinterpret_cast<uint64_t*>(RvaPtr(static_cast<uint32_t>(thunk)));
            else
                thunkValue = *reinterpret_cast<uint32_t*>(RvaPtr(static_cast<uint32_t>(thunk)));

            if (thunkValue == 0)
                break;

            std::string apiName;
            if ((!m_is64 && IMAGE_SNAP_BY_ORDINAL32(static_cast<DWORD>(thunkValue))) ||
                (m_is64 && IMAGE_SNAP_BY_ORDINAL64(thunkValue)))
            {
                apiName = "#ordinal";
            }
            else
            {
                auto byName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(RvaPtr(static_cast<uint32_t>(thunkValue)));
                if (!byName)
                {
                    SetError("invalid import name");
                    return false;
                }
                apiName = reinterpret_cast<const char*>(byName->Name);
            }

            const uint32_t stackBytes = m_is64 ? 0 : GuessX86StackBytes(apiName);
            const uint64_t stub = AllocateImportStub(dll, apiName, stackBytes);

            if (m_is64)
                *reinterpret_cast<uint64_t*>(RvaPtr(static_cast<uint32_t>(iat))) = stub;
            else
                *reinterpret_cast<uint32_t*>(RvaPtr(static_cast<uint32_t>(iat))) = static_cast<uint32_t>(stub);

            thunk += m_is64 ? sizeof(uint64_t) : sizeof(uint32_t);
            iat += m_is64 ? sizeof(uint64_t) : sizeof(uint32_t);
        }

        ++importDesc;
    }

    return true;
}

bool SimplePeEmu::OpenEngine()
{
    const uc_mode mode = m_is64 ? UC_MODE_64 : UC_MODE_32;
    const uc_err err = uc_open(UC_ARCH_X86, mode, &m_uc);
    if (err != UC_ERR_OK)
    {
        SetError(std::string("uc_open failed: ") + uc_strerror(err));
        return false;
    }

    return true;
}

bool SimplePeEmu::MapImageAndStack()
{
    uc_err err = uc_mem_map(m_uc, m_imageBase, AlignUp(m_sizeOfImage, 0x1000), UC_PROT_ALL);
    if (err != UC_ERR_OK)
    {
        SetError(std::string("uc_mem_map image failed: ") + uc_strerror(err));
        return false;
    }

    err = uc_mem_write(m_uc, m_imageBase, m_image.data(), m_image.size());
    if (err != UC_ERR_OK)
    {
        SetError(std::string("uc_mem_write image failed: ") + uc_strerror(err));
        return false;
    }

    m_fakeBase = m_is64 ? 0x700000000000ull : 0x70000000ull;
    err = uc_mem_map(m_uc, m_fakeBase, m_fakeSize, UC_PROT_EXEC | UC_PROT_READ);
    if (err != UC_ERR_OK)
    {
        SetError(std::string("uc_mem_map import stubs failed: ") + uc_strerror(err));
        return false;
    }

    const uint8_t ret = 0xC3;
    for (const auto& item : m_imports)
        uc_mem_write(m_uc, item.first, &ret, sizeof(ret));

    m_stackBase = m_is64 ? 0x100000000ull : 0x1000000ull;
    err = uc_mem_map(m_uc, m_stackBase, m_stackSize, UC_PROT_READ | UC_PROT_WRITE);
    if (err != UC_ERR_OK)
    {
        SetError(std::string("uc_mem_map stack failed: ") + uc_strerror(err));
        return false;
    }

    uint64_t sp = m_stackBase + m_stackSize - 0x100;
    if (m_is64)
    {
        sp &= ~0xfull;
        uc_reg_write(m_uc, UC_X86_REG_RSP, &sp);
        uc_reg_write(m_uc, UC_X86_REG_RBP, &sp);
    }
    else
    {
        uint32_t esp = static_cast<uint32_t>(sp);
        uc_reg_write(m_uc, UC_X86_REG_ESP, &esp);
        uc_reg_write(m_uc, UC_X86_REG_EBP, &esp);
    }

    return true;
}

bool SimplePeEmu::InstallHooks()
{
    uc_err err = uc_hook_add(m_uc, &m_codeHook, UC_HOOK_CODE, reinterpret_cast<void*>(CodeHook), this, m_fakeBase, m_fakeBase + m_fakeSize - 1);
    if (err != UC_ERR_OK)
    {
        SetError(std::string("uc_hook_add code failed: ") + uc_strerror(err));
        return false;
    }

    err = uc_hook_add(m_uc, &m_invalidHook, UC_HOOK_MEM_INVALID, reinterpret_cast<void*>(InvalidMemHook), this, 1, 0);
    if (err != UC_ERR_OK)
    {
        SetError(std::string("uc_hook_add invalid memory failed: ") + uc_strerror(err));
        return false;
    }

    return true;
}

void SimplePeEmu::SetError(const std::string& message)
{
    m_lastError = message;
}

uint64_t SimplePeEmu::AllocateImportStub(const std::string& dllName, const std::string& apiName, uint32_t stackBytes)
{
    if (m_nextFake == 0)
        m_nextFake = m_is64 ? 0x700000000000ull : 0x70000000ull;

    const uint64_t address = m_nextFake++;
    m_imports[address] = ImportEntry{ dllName, apiName, stackBytes };
    return address;
}

uint64_t SimplePeEmu::RvaToOffset(uint32_t rva) const
{
    const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(m_file.data());
    const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(m_file.data() + dos->e_lfanew);
    const auto section = IMAGE_FIRST_SECTION(nt);

    if (rva < m_sizeOfHeaders)
        return rva;

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
    {
        const auto& s = section[i];
        const uint32_t sectionSize = std::max(s.Misc.VirtualSize, s.SizeOfRawData);
        if (rva >= s.VirtualAddress && rva < s.VirtualAddress + sectionSize)
            return s.PointerToRawData + (rva - s.VirtualAddress);
    }

    return UINT64_MAX;
}

uint8_t* SimplePeEmu::RvaPtr(uint32_t rva)
{
    if (rva >= m_image.size())
        return nullptr;
    return m_image.data() + rva;
}

uint64_t SimplePeEmu::ReadPointer(uint64_t address) const
{
    uint64_t value = 0;
    if (m_is64)
    {
        uc_mem_read(m_uc, address, &value, sizeof(value));
    }
    else
    {
        uint32_t value32 = 0;
        uc_mem_read(m_uc, address, &value32, sizeof(value32));
        value = value32;
    }
    return value;
}

uint64_t SimplePeEmu::ReadArgument(size_t index) const
{
    if (m_is64)
    {
        uint64_t value = 0;
        switch (index)
        {
        case 0: uc_reg_read(m_uc, UC_X86_REG_RCX, &value); return value;
        case 1: uc_reg_read(m_uc, UC_X86_REG_RDX, &value); return value;
        case 2: uc_reg_read(m_uc, UC_X86_REG_R8, &value); return value;
        case 3: uc_reg_read(m_uc, UC_X86_REG_R9, &value); return value;
        default:
            uint64_t rsp = 0;
            uc_reg_read(m_uc, UC_X86_REG_RSP, &rsp);
            return ReadPointer(rsp + 0x28 + (index - 4) * sizeof(uint64_t));
        }
    }

    uint32_t esp = 0;
    uc_reg_read(m_uc, UC_X86_REG_ESP, &esp);
    return ReadPointer(static_cast<uint64_t>(esp) + sizeof(uint32_t) + index * sizeof(uint32_t));
}

bool SimplePeEmu::ReadAnsiString(uint64_t address, std::string& out, size_t maxLen) const
{
    out.clear();
    for (size_t i = 0; i < maxLen; ++i)
    {
        char ch = 0;
        if (uc_mem_read(m_uc, address + i, &ch, sizeof(ch)) != UC_ERR_OK)
            return false;
        if (ch == 0)
            return true;
        out.push_back(ch);
    }
    return false;
}

bool SimplePeEmu::ReturnFromImport(uint64_t returnValue, uint32_t stackBytes)
{
    uint64_t sp = 0;
    if (m_is64)
        uc_reg_read(m_uc, UC_X86_REG_RSP, &sp);
    else
    {
        uint32_t esp = 0;
        uc_reg_read(m_uc, UC_X86_REG_ESP, &esp);
        sp = esp;
    }

    const uint64_t returnAddress = ReadPointer(sp);
    const uint64_t newSp = sp + (m_is64 ? sizeof(uint64_t) : sizeof(uint32_t)) + stackBytes;

    if (m_is64)
    {
        uc_reg_write(m_uc, UC_X86_REG_RAX, &returnValue);
        uc_reg_write(m_uc, UC_X86_REG_RSP, &newSp);
        uc_reg_write(m_uc, UC_X86_REG_RIP, &returnAddress);
    }
    else
    {
        const uint32_t eax = static_cast<uint32_t>(returnValue);
        const uint32_t esp = static_cast<uint32_t>(newSp);
        const uint32_t eip = static_cast<uint32_t>(returnAddress);
        uc_reg_write(m_uc, UC_X86_REG_EAX, &eax);
        uc_reg_write(m_uc, UC_X86_REG_ESP, &esp);
        uc_reg_write(m_uc, UC_X86_REG_EIP, &eip);
    }

    return true;
}

void SimplePeEmu::HandleImport(uint64_t address)
{
    const auto iter = m_imports.find(address);
    if (iter == m_imports.end())
        return;

    const ImportEntry& import = iter->second;
    const std::string api = ToLower(import.apiName);

    if (api == "getstdhandle")
    {
        ReturnFromImport(static_cast<uint64_t>(static_cast<int64_t>(-11)), import.stackBytes);
        return;
    }

    if (api == "writefile")
    {
        const uint64_t buffer = ReadArgument(1);
        const uint32_t bytesToWrite = static_cast<uint32_t>(ReadArgument(2));
        const uint64_t bytesWritten = ReadArgument(3);

        std::vector<char> data(bytesToWrite);
        if (!data.empty() && uc_mem_read(m_uc, buffer, data.data(), data.size()) == UC_ERR_OK)
            std::cout.write(data.data(), data.size());

        if (bytesWritten)
            uc_mem_write(m_uc, bytesWritten, &bytesToWrite, sizeof(bytesToWrite));

        ReturnFromImport(1, import.stackBytes);
        return;
    }

    if (api == "exitprocess")
    {
        uint32_t code = static_cast<uint32_t>(ReadArgument(0));
        uc_reg_write(m_uc, m_is64 ? UC_X86_REG_RAX : UC_X86_REG_EAX, &code);
        uc_emu_stop(m_uc);
        return;
    }

    std::cout << "[emu] " << import.dllName << "!" << import.apiName << " -> default 0\n";
    ReturnFromImport(0, import.stackBytes);
}

void SimplePeEmu::CodeHook(uc_engine* uc, uint64_t address, uint32_t size, void* userData)
{
    auto self = static_cast<SimplePeEmu*>(userData);
    self->HandleImport(address);
}

bool SimplePeEmu::InvalidMemHook(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* userData)
{
    auto self = static_cast<SimplePeEmu*>(userData);
    char message[128] = {};
    sprintf_s(message, "invalid memory access type=%d address=0x%llX", static_cast<int>(type), static_cast<unsigned long long>(address));
    self->SetError(message);
    uc_emu_stop(uc);
    return false;
}
