#include "Scanner.h"

namespace scanner
{
    std::vector<std::optional<uint8_t>> parse_ida_signature(const char* sig) {
        std::vector<std::optional<uint8_t>> bytes;
        std::stringstream ss(sig);

        while (!ss.eof()) {
            std::string byte_str;
            ss >> byte_str;

            if (byte_str == "?" || byte_str == "??") {
                bytes.push_back(std::nullopt);
                continue;
            }

            if (byte_str.length() != 2) {
                throw std::runtime_error("Invalid byte in IDA signature: " + byte_str);
            }

            char* end;
            long value = strtol(byte_str.c_str(), &end, 16);

            if (*end != '\0') {
                throw std::runtime_error("Invalid byte in IDA signature: " + byte_str);
            }

            bytes.push_back(static_cast<uint8_t>(value));
        }

        return bytes;
    }


    pattern::pattern(const std::string& module) : m_module(module.c_str()), m_module_name(module), m_result(0, (uintptr_t)0)
    {
        m_module_handle = LoadLibraryA(m_module_name.c_str());

        if (m_module_handle == nullptr) {
            throw std::runtime_error("Could not find module: " + m_module_name);
        }

        MODULEINFO mi = { 0 };

        if (!GetModuleInformation(GetCurrentProcess(), m_module_handle, &mi, sizeof(mi))) {
            throw std::runtime_error("Could not get module information");
        }
        m_module_size = mi.SizeOfImage;
    }

    pattern::~pattern()
    {
        if (m_module_handle) FreeLibrary(m_module_handle);
    }

    pattern& pattern::scan_now(const char* sig_name, const char* ida_sig, const char* section_name)
    {
        auto signature = parse_ida_signature(ida_sig);

        std::uintptr_t base_address = reinterpret_cast<std::uintptr_t>(m_module_handle);

        std::size_t sig_size = signature.size();
        std::uintptr_t end_address = base_address + m_module_size - sig_size;

        std::array<int, 256> bad_char;
        for (int i = 0; i < 256; ++i) {
            bad_char[i] = sig_size;
        }
        for (int i = 0; i < sig_size - 1; ++i) {
            if (signature[i].has_value()) {
                bad_char[signature[i].value()] = sig_size - i - 1;
            }
            else {
                for (int j = 0; j < 256; ++j) {
                    bad_char[j] = min(bad_char[j], sig_size - i - 1);
                }
            }
        }

        std::uintptr_t i = 0;
        if (section_name == nullptr) i = base_address + sig_size - 1;
        else
        {
            PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)base_address;
            PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)base_address + pDosHeader->e_lfanew);
            PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

            LPVOID lpFoundAddress = NULL;

            for (WORD j = 0; j < pNtHeaders->FileHeader.NumberOfSections; j++)
            {
                if (strcmp((CHAR*)pSectionHeader[j].Name, section_name) == 0)
                {
                    lpFoundAddress = (LPVOID)((LPBYTE)base_address + pSectionHeader[j].VirtualAddress);
                    i = (uintptr_t)lpFoundAddress + sig_size - 1;

                    SIZE_T dwSectionSize = pSectionHeader[j].Misc.VirtualSize;
                    end_address = (uintptr_t)lpFoundAddress + dwSectionSize - sig_size;
                    break;
                }
            }

            if (lpFoundAddress == NULL)
            {
                throw std::runtime_error(std::string("Section ") + section_name + " not found!");
            }
        }

        while (i < end_address) {
            int j = sig_size - 1;
            while (j >= 0) {
                if (signature[j].has_value() && signature[j].value() != *reinterpret_cast<uint8_t*>(i - sig_size + j + 1))
                    break;
                --j;
            }
            if (j < 0) {
                m_result = handle(i - sig_size + 1, (uintptr_t)m_module_handle);
                return *this;
            }
            i += max(bad_char[*reinterpret_cast<uint8_t*>(i)], static_cast<int>(sig_size - j - 1));
        }

        m_result = handle(0, (uintptr_t)m_module_handle);

        return *this;
    }

    handle pattern::get_result()
    {
        return m_result;
    }
}