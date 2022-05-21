#pragma once
#include <Windows.h>
#include <string>
class imphash
{
public:
    static std::string get_imphash(const wchar_t* const filename);

private:
    static std::string calc(const void* const base);
};

