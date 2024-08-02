#pragma once
// IDA search pattern library
// 4l3x777

#include <cstdint>   
#include <string>   
#include <Windows.h> 
#include <Psapi.h>
#include <vector>
#include <optional>
#include <sstream>
#include <array>

namespace scanner
{
    class handle {
    public:
        handle() = default;
        explicit handle(uintptr_t address, uintptr_t module_handle) : m_address(address), m_module_handle(module_handle) {}

        template <typename T>
        T as() const {
            return reinterpret_cast<T>(m_address);
        }

        handle add(uintptr_t offset) const {
            if (m_address != 0)
            {
                return handle(m_address + offset, m_module_handle);
            }

            return *this;
        }

        handle sub(uintptr_t offset) const {
            if (m_address != 0)
            {
                return handle(m_address - offset, m_module_handle);
            }

            return *this;
        }

        handle rip() const {
            if (m_address != 0)
            {
                auto offset = *as<int32_t*>();
                return add(offset + sizeof(int32_t));
            }

            return *this;
        }

        template <typename T>
        T get_base() const {
            return reinterpret_cast<T>(m_module_handle);
        }

    private:
        uintptr_t m_address = 0;
        uintptr_t m_module_handle = 0;
    };


    class _module {
    public:
        _module(const char* module) : m_module(module)
        {
            m_module_handle = LoadLibraryA(m_module);
        }

        handle get_export(const char* func)
        {
            return handle((std::uintptr_t)GetProcAddress(m_module_handle, func), (std::uintptr_t)m_module_handle);
        }

        HMODULE get_handle()
        {
            return m_module_handle;
        }

    private:
        const char* m_module;
        HMODULE m_module_handle;
    };

    class pattern {
    public:
        pattern(const std::string& module);
        ~pattern() noexcept;

        pattern& scan_now(const char* sig_name, const char* ida_sig, const char* section_name = nullptr);

        handle get_result();

    private:
        std::string m_module_name;
        _module m_module;
        size_t m_module_size;
        HMODULE m_module_handle;
        handle m_result;
    };
}