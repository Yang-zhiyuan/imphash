#include "imphash.h"
#include <ios>
#include <sstream>
#include <vector>
#include <Wincrypt.h>
#include <Windows.h>
#include "ordinal.h"
#include "Pe.hpp"


enum HashType
{
    HashSha1,
    HashMd5,
    HashSha256
};

std::string GetHashText(const void* data, const size_t data_size, HashType hashType)
{
    HCRYPTPROV hProv = NULL;

    if (! CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        return "";
    }

    BOOL hash_ok = FALSE;
    HCRYPTPROV hHash = NULL;
    switch (hashType)
    {
    case HashSha1: hash_ok = CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash);
        break;
    case HashMd5: hash_ok = CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash);
        break;
    case HashSha256: hash_ok = CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
        break;
    }

    if (!hash_ok)
    {
        CryptReleaseContext(hProv, 0);
        return "";
    }

    if (!CryptHashData(hHash, static_cast<const BYTE*>(data), data_size, 0))
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    DWORD cbHashSize = 0, dwCount = sizeof(DWORD);
    if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&cbHashSize, &dwCount, 0))
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    std::vector<BYTE> buffer(cbHashSize);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, &buffer[0], &cbHashSize, 0))
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    std::ostringstream oss;

    for (const auto& value : buffer)
    {
        oss.fill('0');
        oss.width(2);
        oss << std::hex << static_cast<int>(value);
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return oss.str();
}

std::string imphash::get_imphash(const wchar_t* const filename)
{
    std::string hash;
    const auto file = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 nullptr,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file != INVALID_HANDLE_VALUE)
    {
        if (const auto mapping = CreateFileMapping(file, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr))
        {
            if (const auto base = MapViewOfFileEx(mapping, FILE_MAP_READ, 0, 0, 0, nullptr))
            {
                hash = calc(base);
                UnmapViewOfFile(base);
            }
            CloseHandle(mapping);
        }
        CloseHandle(file);
    }

    return hash;
}

static auto GetModuleName = [](const char* const module_name)-> std::string
{
    const char* extension[3] = {
        "dll",
        "ocx",
        "sys"
    };

    if (auto pos = strrchr(module_name, '.'); pos)
    {
        pos++;
        for (const auto& ext : extension)
        {
            if (_stricmp(pos, ext) == 0)
            {
                return std::string(module_name, pos - 1);
            }
        }
    }

    return module_name;
};

static auto GetOrdinalName = [](const char* const module_name, unsigned short ordinal)-> std::string
{
    using modules = struct
    {
        const char* const module_name;
        const ord_t* const functions;
        unsigned short ordinal;
    };

    constexpr modules mod[3] = {
        {"oleaut32.dll", oleaut32_arr, _countof(oleaut32_arr)},
        {"ws2_32.dll", ws2_32_arr, _countof(ws2_32_arr)},
        {"wsock32.dll", ws2_32_arr, _countof(ws2_32_arr)}
    };

    for (const auto& [module_name_, ord_name, size] : mod)
    {
        if (_stricmp(module_name, module_name_) == 0)
        {
            for (int i = 0; i < size; ++i)
            {
                if (ordinal == ord_name[i].number)
                {
                    return ord_name[i].fname;
                }
            }
        }
    }

    return std::string("ord") + std::to_string(ordinal);
};

template <Pe::Arch Arch>
std::string GetImportHash(const void* base)
{
    auto pe = Pe::Pe<Arch>::fromModule(base);
    if (pe.valid())
    {
        std::string result;
        for (const auto& module_entry : pe.imports())
        {
            const char* module_name = module_entry.libName();
            for (const auto& entry : module_entry)
            {
                if (entry.type() == Pe::ImportType::unknown)
                {
                    continue;
                }

                auto name = GetModuleName(module_name);
                result.append(name);
                result.append(".");

                switch (entry.type())
                {
                case Pe::ImportType::name:
                    {
                        result.append(entry.name()->Name);
                        break;
                    }
                case Pe::ImportType::ordinal:
                    {
                        result.append(GetOrdinalName(module_name, entry.ordinal()));
                        break;
                    }
                }

                result.append(",");
            }
        }

        if (!result.empty())
        {
            result.erase(--result.end());
            CharLowerA(result.data());
            return GetHashText(result.c_str(), result.size(), HashMd5);
        }
    }

    return {};
}

std::string imphash::calc(const void* const base)
{
    const auto dos_header = PIMAGE_DOS_HEADER(base);
    const auto pe_header = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<size_t>(base) + dos_header->e_lfanew);
    if (pe_header->FileHeader.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER64))
    {
        return GetImportHash<Pe::Arch::x64>(base);
    }
    if (pe_header->FileHeader.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER32))
    {
        return GetImportHash<Pe::Arch::x32>(base);
    }

    return {};
}
