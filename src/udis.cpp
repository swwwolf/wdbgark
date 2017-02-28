/*
    * WinDBG Anti-RootKit extension
    * Copyright © 2013-2017  Vyacheslav Rusakoff
    * 
    * This program is free software: you can redistribute it and/or modify
    * it under the terms of the GNU General Public License as published by
    * the Free Software Foundation, either version 3 of the License, or
    * (at your option) any later version.
    * 
    * This program is distributed in the hope that it will be useful,
    * but WITHOUT ANY WARRANTY; without even the implied warranty of
    * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    * GNU General Public License for more details.
    * 
    * You should have received a copy of the GNU General Public License
    * along with this program.  If not, see <http://www.gnu.org/licenses/>.

    * This work is licensed under the terms of the GNU GPL, version 3.  See
    * the COPYING file in the top-level directory.
*/

#include "udis.hpp"
#include <engextcpp.hpp>

#include <memory>
#include <sstream>
#include <string>

#include "manipulators.hpp"

namespace wa {

void WDbgArkUdis::Init(const uint8_t mode) {
    std::memset(&m_udis_obj, 0, sizeof(m_udis_obj));
    ud_init(&m_udis_obj);
    ud_set_mode(&m_udis_obj, mode);
    ud_set_syntax(&m_udis_obj, UD_SYN_INTEL);

    DEBUG_PROCESSOR_IDENTIFICATION_ALL processor_info;
    HRESULT result = g_Ext->m_Data->ReadProcessorSystemData(0,
                                                            DEBUG_DATA_PROCESSOR_IDENTIFICATION,
                                                            &processor_info,
                                                            static_cast<uint32_t>(sizeof(processor_info)),
                                                            nullptr);

    uint32_t vendor = UD_VENDOR_ANY;

    if (SUCCEEDED(result) &&
        (g_Ext->m_ActualMachine == IMAGE_FILE_MACHINE_I386 || g_Ext->m_ActualMachine == IMAGE_FILE_MACHINE_AMD64) ) {
            std::string vendor_string;

            if ( g_Ext->m_ActualMachine == IMAGE_FILE_MACHINE_I386 )
                vendor_string = processor_info.X86.VendorString;
            else
                vendor_string = processor_info.Amd64.VendorString;

            if ( vendor_string == "GenuineIntel" )
                vendor = UD_VENDOR_INTEL;
            else
                vendor = UD_VENDOR_AMD;
    }

    ud_set_vendor(&m_udis_obj, vendor);
}

WDbgArkUdis::WDbgArkUdis() {
    uint8_t mode = 0;

    if ( g_Ext->IsCurMachine32() )
        mode = 32;
    else
        mode = 64;

    Init(mode);
    m_inited = true;
}

WDbgArkUdis::WDbgArkUdis(uint8_t mode, uint64_t address, size_t size)  {
    uint8_t init_mode = mode;

    if ( !init_mode ) {
        if ( g_Ext->IsCurMachine32() )
            init_mode = 32;
        else
            init_mode = 64;
    }

    Init(init_mode);
    m_inited = SetInputBuffer(address, size);
}

bool WDbgArkUdis::SetInputBuffer(const uint8_t* buffer, const size_t size) {
    if ( !IsInited() ) {
        err << wa::showminus << __FUNCTION__ << ": class is not initialized" << endlerr;
        return false;
    }

    m_buffer.reset(new uint8_t[size]);
    std::memcpy(m_buffer.get(), reinterpret_cast<const void*>(buffer), size);
    ud_set_input_buffer(&m_udis_obj, m_buffer.get(), size);
    SetInstructionPointer(0ULL);
    m_size = size;

    return true;
}

bool WDbgArkUdis::SetInputBuffer(const uint64_t address, const size_t size) {
    try {
        ExtRemoteData data(address, static_cast<uint32_t>(size));
        m_buffer.reset(new uint8_t[size]);
        data.ReadBuffer(reinterpret_cast<void*>(m_buffer.get()), static_cast<uint32_t>(size), true);
        ud_set_input_buffer(&m_udis_obj, m_buffer.get(), size);
        SetInstructionPointer(address);
        m_size = size;

        return true;
    }
    catch (const ExtRemoteException &Ex) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    return false;
}

}   // namespace wa
