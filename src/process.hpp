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

//////////////////////////////////////////////////////////////////////////
//  Include this after "#define EXT_CLASS WDbgArk" only
//////////////////////////////////////////////////////////////////////////

#if _MSC_VER > 1000
#pragma once
#endif

#ifndef PROCESS_HPP_
#define PROCESS_HPP_

#include <engextcpp.hpp>

#include <string>
#include <sstream>
#include <vector>
#include <utility>
#include <memory>

#include "dummypdb.hpp"

namespace wa {

class WDbgArkProcess {
 public:
    typedef struct ProcessInfoTag {
        ExtRemoteTyped process;
        uint64_t eprocess;
        std::string image_file_name;
        bool is_wow64;
    } ProcessInfo;

    using ProcessList = std::vector<ProcessInfo>;

    WDbgArkProcess();
    // provide dummy pdb shared pointer here if you wanna get instrumentation callback info
    explicit WDbgArkProcess(const std::shared_ptr<WDbgArkDummyPdb> &dummy_pdb);
    ~WDbgArkProcess();

    bool IsInited(void) const { return m_inited; }
    const auto& GetProcessList() const { return m_process_list; }

    uint64_t FindEProcessByImageFileName(const std::string &process_name);
    uint64_t FindEProcessAnyGUIProcess();
    uint64_t FindEProcessAnyApiSetMap();
    uint64_t GetProcessApiSetMap(const ProcessInfo &info);
    uint64_t GetProcessApiSetMap(const uint64_t &eprocess);
    uint64_t GetProcessApiSetMap(const ExtRemoteTyped &process);

    HRESULT SetImplicitProcess(const uint64_t set_eprocess);
    HRESULT SetImplicitProcess(const ExtRemoteTyped &set_eprocess);
    HRESULT RevertImplicitProcess();

    uint64_t GetInstrumentationCallback(const ProcessInfo &info);

 private:
    std::pair<bool, std::string> GetProcessImageFileName(const ExtRemoteTyped &process);
    uint64_t GetProcessDataOffset(const ExtRemoteTyped &process) const { return process.m_Offset; }
    bool FindProcessInfoByImageFileName(const std::string &process_name, ProcessInfo* info);
    bool IsWow64Process(const ExtRemoteTyped &process);
    uint64_t GetWow64ProcessPeb32(const ProcessInfo &info);
    uint64_t GetWow64ProcessPeb32(const ExtRemoteTyped &process);
    uint64_t GetWow64InfoPtr(const ProcessInfo &info);
    uint64_t GetWow64InfoPtr(const ExtRemoteTyped &process);
    uint64_t GetWow64InstrumentationCallback(const ProcessInfo &info);

 private:
    bool m_inited = false;
    bool m_new_wow64 = false;
    std::string m_wow64_proc_field_name{};
    uint64_t m_old_process = 0ULL;
    ProcessList m_process_list{};
    std::shared_ptr<WDbgArkDummyPdb> m_dummy_pdb{ nullptr };
    ExtCheckedPointer<IDebugSystemObjects2> m_System2{ "The extension did not initialize properly." };
};

}   // namespace wa

#endif  // PROCESS_HPP_
