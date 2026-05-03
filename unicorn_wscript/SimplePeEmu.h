#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include <unicorn/unicorn.h>

class SimplePeEmu
{
public:
    SimplePeEmu();
    ~SimplePeEmu();

    bool Load(const std::wstring& path);
    bool Run();
    const std::string& LastError() const { return m_lastError; }

private:
    struct ImportEntry
    {
        std::string dllName;
        std::string apiName;
        uint32_t stackBytes;
    };

    bool ReadFileToBuffer(const std::wstring& path);
    bool ParseHeaders();
    bool BuildImage();
    bool ResolveImports();
    bool OpenEngine();
    bool MapImageAndStack();
    bool InstallHooks();
    void SetError(const std::string& message);

    uint64_t AllocateImportStub(const std::string& dllName, const std::string& apiName, uint32_t stackBytes);
    uint64_t RvaToOffset(uint32_t rva) const;
    uint8_t* RvaPtr(uint32_t rva);
    uint64_t ReadPointer(uint64_t address) const;
    uint64_t ReadArgument(size_t index) const;
    bool ReadAnsiString(uint64_t address, std::string& out, size_t maxLen = 4096) const;
    bool ReturnFromImport(uint64_t returnValue, uint32_t stackBytes);
    void HandleImport(uint64_t address);

    static void CodeHook(uc_engine* uc, uint64_t address, uint32_t size, void* userData);
    static bool InvalidMemHook(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* userData);

private:
    std::wstring m_path;
    std::string m_lastError;
    std::vector<uint8_t> m_file;
    std::vector<uint8_t> m_image;

    uc_engine* m_uc;
    uc_hook m_codeHook;
    uc_hook m_invalidHook;

    bool m_is64;
    uint16_t m_machine;
    uint64_t m_imageBase;
    uint64_t m_imageEnd;
    uint32_t m_sizeOfImage;
    uint32_t m_sizeOfHeaders;
    uint32_t m_entryRva;
    uint32_t m_importRva;
    uint32_t m_importSize;

    uint64_t m_stackBase;
    uint64_t m_stackSize;
    uint64_t m_fakeBase;
    uint64_t m_fakeSize;
    uint64_t m_nextFake;

    std::map<uint64_t, ImportEntry> m_imports;
};
