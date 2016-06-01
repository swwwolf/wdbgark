/*
    * WinDBG Anti-RootKit extension
    * Copyright © 2013-2016  Vyacheslav Rusakoff
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

#include <string>
#include <vector>
#include <algorithm>
#include <utility>
#include <memory>

#include "process.hpp"
#include "wdbgark.hpp"
#include "manipulators.hpp"

namespace wa {

WDbgArkProcess::WDbgArkProcess() {
    try {
        if ( GetTypeSize("nt!_EWOW64PROCESS") )
            m_new_wow64 = true;     // 10586+

        ExtRemoteTypedList list_head = ExtNtOsInformation::GetKernelProcessList();

        for ( list_head.StartHead(); list_head.HasNode(); list_head.Next() ) {
            ProcessInfo info;
            info.process = list_head.GetTypedNode();
            info.eprocess = GetProcessDataOffset(info.process);

            if ( m_wow64_proc_field_name.empty() && g_Ext->IsCurMachine64() ) {
                if ( info.process.HasField("WoW64Process") )
                    m_wow64_proc_field_name = "WoW64Process";
                else
                    m_wow64_proc_field_name = "Wow64Process";
            }

            std::pair<bool, std::string> result = GetProcessImageFileName(info.process);

            if ( !result.first ) {
                warn << wa::showqmark << __FUNCTION__ << ": failed to read process file name ";
                warn << std::hex << std::showbase << info.process.m_Offset << endlwarn;
            } else {
                std::string image_file_name = result.second;
                std::transform(image_file_name.begin(), image_file_name.end(), image_file_name.begin(), tolower);
                info.image_file_name = image_file_name;
            }

            info.is_wow64 = IsWow64Process(info.process);

            m_process_list.push_back(info);
        }

        if ( !m_process_list.empty() )
            m_inited = true;
    }
    catch( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
}

WDbgArkProcess::WDbgArkProcess(const std::shared_ptr<WDbgArkDummyPdb> &dummy_pdb) : WDbgArkProcess() {
    m_dummy_pdb = dummy_pdb;
}

WDbgArkProcess::~WDbgArkProcess() {
    RevertImplicitProcess();
}

uint64_t WDbgArkProcess::FindEProcessByImageFileName(const std::string &process_name) {
    ProcessInfo info;

    if ( !IsInited() ) {
        err << wa::showminus << __FUNCTION__ << ": class is not initialized" << endlerr;
        return 0ULL;
    }

    if ( FindProcessInfoByImageFileName(process_name, &info) )
        return info.eprocess;

    return 0ULL;
}

uint64_t WDbgArkProcess::FindEProcessAnyGUIProcess() {
    if ( !IsInited() ) {
        err << wa::showminus << __FUNCTION__ << ": class is not initialized" << endlerr;
        return 0ULL;
    }

    try {
        std::vector<ProcessInfo>::iterator it =\
            std::find_if(std::begin(m_process_list), std::end(m_process_list), [](ProcessInfo &proc_info) {
                return proc_info.process.Field("Win32Process").GetPtr() != 0ULL; });

        if ( it != std::end(m_process_list) )
            return it->eprocess;
    }
    catch( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    return 0ULL;
}

HRESULT WDbgArkProcess::SetImplicitProcess(const uint64_t set_eprocess) {
    if ( !IsInited() ) {
        err << wa::showminus << __FUNCTION__ << ": class is not initialized" << endlerr;
        return E_UNEXPECTED;
    }

    if ( m_old_process ) {
        err << wa::showminus << __FUNCTION__ << ": implicit process already set" << endlerr;
        return E_INVALIDARG;
    }

    HRESULT result = g_Ext->m_System2->GetImplicitProcessDataOffset(&m_old_process);

    if ( !SUCCEEDED(result) ) {
        err << wa::showminus << __FUNCTION__ << ": failed to get current EPROCESS" << endlerr;
        return result;
    }

    if ( m_old_process == set_eprocess ) {
        m_old_process = 0ULL;
        return S_OK;
    }

    result = g_Ext->m_System2->SetImplicitProcessDataOffset(set_eprocess);

    if ( !SUCCEEDED(result) ) {
        err << wa::showminus << __FUNCTION__ << ": failed to set implicit process to ";
        err << std::hex << std::showbase << set_eprocess << endlerr;
    }

    return result;
}

HRESULT WDbgArkProcess::RevertImplicitProcess() {
    if ( !IsInited() ) {
        err << wa::showminus << __FUNCTION__ << ": class is not initialized" << endlerr;
        return E_UNEXPECTED;
    }

    HRESULT result = E_NOT_SET;

    if ( m_old_process ) {
        result = g_Ext->m_System2->SetImplicitProcessDataOffset(m_old_process);

        if ( !SUCCEEDED(result) )
            err << wa::showminus << __FUNCTION__ << ": failed to revert" << endlerr;
        else
            m_old_process = 0ULL;
    }

    return result;
}

// 6000 - 9600 x64 only
// 10240+ x86/x64 ()
uint64_t WDbgArkProcess::GetInstrumentationCallback(const ProcessInfo &info) {
    if ( !IsInited() ) {
        err << wa::showminus << __FUNCTION__ << ": class is not initialized" << endlerr;
        return 0ULL;
    }

    try {
        if ( g_Ext->IsCurMachine64() ) {
            if ( !info.is_wow64 ) {
                // native x64 process: _EPROCESS->_KPROCESS->InstrumentationCallback
                return const_cast<ExtRemoteTyped&>(info.process).Field("Pcb").Field("InstrumentationCallback").GetPtr();
            } else {
                // WOW64 process
                return GetWow64InstrumentationCallback(info);
            }
        } else {
            // 10240+ x86 process only: _EPROCESS->InstrumentationCallback
            return const_cast<ExtRemoteTyped&>(info.process).Field("InstrumentationCallback").GetPtr();
        }
    } catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    return 0ULL;
}

std::pair<bool, std::string> WDbgArkProcess::GetProcessImageFileName(const ExtRemoteTyped &process) {
    std::string output_name = "";

    try {
        char buffer[100] = {0};
        ExtRemoteTyped image_file_name = const_cast<ExtRemoteTyped&>(process).Field("ImageFileName");
        output_name = image_file_name.GetString(buffer,
                                                static_cast<ULONG>(sizeof(buffer)),
                                                image_file_name.GetTypeSize(),
                                                false);
        return std::make_pair(true, output_name);
    }
    catch( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    return std::make_pair(false, output_name);
}

bool WDbgArkProcess::FindProcessInfoByImageFileName(const std::string &process_name, ProcessInfo* info) {
    std::string compare_with = process_name;
    std::transform(compare_with.begin(), compare_with.end(), compare_with.begin(), tolower);

    std::vector<ProcessInfo>::iterator it =\
        std::find_if(m_process_list.begin(), m_process_list.end(), [&compare_with](const ProcessInfo &proc_info) {
            return proc_info.image_file_name == compare_with; });

    if ( it != m_process_list.end() ) {
        *info = *it;
        return true;
    }

    return false;
}

bool WDbgArkProcess::IsWow64Process(const ExtRemoteTyped &process) {
    if ( g_Ext->IsCurMachine32() )
        return false;

    try {
        return (const_cast<ExtRemoteTyped&>(process).Field(m_wow64_proc_field_name.c_str()).GetPtr() != 0ULL);
    } catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    return false;
}

uint64_t WDbgArkProcess::GetWow64ProcessPeb32(const ProcessInfo &info) {
    if ( !info.is_wow64 )
        return 0ULL;

    return GetWow64ProcessPeb32(info.process);
}

uint64_t WDbgArkProcess::GetWow64ProcessPeb32(const ExtRemoteTyped &process) {
    try {
        if ( m_new_wow64 ) {
            return const_cast<ExtRemoteTyped&>(process).Field(m_wow64_proc_field_name.c_str()).Field("Peb").GetPtr();
        } else {
            return const_cast<ExtRemoteTyped&>(process).Field(m_wow64_proc_field_name.c_str()).GetPtr();
        }
    } catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    return 0ULL;
}

uint64_t WDbgArkProcess::GetWow64InfoPtr(const ProcessInfo &info) {
    if ( !info.is_wow64 )
        return 0ULL;

    return GetWow64InfoPtr(info.process);
}

uint64_t WDbgArkProcess::GetWow64InfoPtr(const ExtRemoteTyped &process) {
    uint64_t wow64peb = GetWow64ProcessPeb32(process);

    if ( !wow64peb )
        return 0ULL;

    return wow64peb + GetTypeSize("nt!_PEB32");
}

uint64_t WDbgArkProcess::GetWow64InstrumentationCallback(const ProcessInfo &info) {
    uint64_t offset = GetWow64InfoPtr(info);

    if ( !offset )
        return 0ULL;

    if ( FAILED(SetImplicitProcess(info.eprocess)) )
        return 0ULL;

    uint64_t address = 0ULL;

    try {
        ExtRemoteTyped wow64info((m_dummy_pdb->GetShortName() + "!_WOW64_INFO").c_str(),
                                 offset,
                                 false,
                                 nullptr,
                                 nullptr);
        address = static_cast<uint64_t>(wow64info.Field("InstrumentationCallback").GetUlong());
    } catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    RevertImplicitProcess();
    return address;
}

}   // namespace wa
