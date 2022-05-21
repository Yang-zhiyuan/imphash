#include <iostream>
#include "imphash.h"
#include <Windows.h>

int main()
{
    wchar_t buffer[512] = {};
    if (GetModuleFileName(nullptr, buffer, 512))
    {
        printf(imphash::get_imphash(buffer).c_str());
    }

    return 0;
}