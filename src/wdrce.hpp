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

#if _MSC_VER > 1000
#pragma once
#endif

#ifndef WDRCE_HPP_
#define WDRCE_HPP_

#include <engextcpp.hpp>

#include <string>
#include <sstream>
#include <fstream>
#include <memory>
#include <utility>
#include <unordered_map>

#include "symbols.hpp"
#include "dummypdb.hpp"
#include "pe.hpp"
#include "strings.hpp"
#include "symcache.hpp"

namespace wa {

class WDbgArkRce {
 public:
    using unique_buf = std::unique_ptr<uint8_t[]>;
    using unique_buf_size = std::pair<unique_buf, size_t>;

    typedef enum _WINKD_WORKER_STATE {
        WinKdWorkerReady = 0,
        WinKdWorkerStart,
        WinKdWorkerInitialized
    } WINKD_WORKER_STATE;

    typedef struct CommandInfoTag {
        std::string rce_function_name;
        std::string output;
    } CommandInfo;

    using command_info = std::unordered_map<std::string, CommandInfo>;          // function name : command info
    using shellcode_info = std::unordered_map<std::string, unique_buf_size>;    // function name : shellcode info

    WDbgArkRce(const std::shared_ptr<WDbgArkSymbolsBase> &symbols_base,
               const std::shared_ptr<WDbgArkDummyPdb> &dummy_pdb,
               const std::shared_ptr<WDbgArkSymCache> &sym_cache);

    WDbgArkRce(const std::shared_ptr<WDbgArkSymbolsBase> &symbols_base,
               const std::shared_ptr<WDbgArkDummyPdb> &dummy_pdb,
               const std::shared_ptr<WDbgArkSymCache> &sym_cache,
               const std::string &temp_module_name);

    WDbgArkRce() = delete;
    ~WDbgArkRce();

    bool IsInited() const { return m_inited; }
    bool Init();
    bool ExecuteCpuid(const int function_id, const int subfunction_id = 0);

 private:
    std::string GetFullPath() const { return m_dummy_rce_full_path; }

    bool InitWdRce();
    bool InitSymbols();
    bool InitGlobalData();
    bool FillGlobalData(const std::string &struct_name,
                        const std::string &field_name,
                        const void* buffer,
                        const size_t size);
    bool InitTempModule();
    bool InitTempModuleCodeSection();
    bool InitTempModuleDataSection();
    ExtRemoteTyped GetDataSectionTyped();
    bool InitRceModule();
    bool InitRceShellcodes();
    bool InitRceShellcode(const std::string &function_name, const std::string &command_name);

    bool SetFunction(const std::string &function_name);
    bool SetOutput(const std::string &output);
    bool SetCpuidParameters(const int function_id, const int subfunction_id = 0);
    bool SetPrintOption(const std::string &option, const std::string &field_name);
    bool SetParameterOption(const std::string &field_name, const void* buffer, const size_t buffer_size);
    bool WriteGlobalData(const unique_buf_size &data);
    bool WriteCodeData(const unique_buf_size &code);
    HRESULT WriteVirtualUncached(const uint64_t address, const unique_buf_size &buffer);
    HRESULT WriteVirtualUncached(const uint64_t address, const void* buffer, const size_t buffer_size);
    HRESULT ReadVirtualUncached(const uint64_t address, const void* buffer, const size_t buffer_size);
    bool HookWorkItem();
    bool HookWorkItemRoutine();
    bool HookWorkItemParameter();
    void UnHookWorkItemParameter();
    void UnHookWorkItemRoutine();
    void UnHookWorkItem();
    bool SetWorkItemState(const WINKD_WORKER_STATE state);
    void RevertTempModule();

 private:
    bool m_inited = false;
    std::shared_ptr<WDbgArkSymbolsBase> m_symbols_base{ nullptr };
    std::shared_ptr<WDbgArkDummyPdb> m_dummy_pdb{ nullptr };
    std::shared_ptr<WDbgArkSymCache> m_sym_cache{ nullptr };
    ExtCheckedPointer<IDebugDataSpaces> m_data_iface{ "The extension did not initialize properly." };

    std::string m_dummy_rce_full_path{};
    std::unique_ptr<WDbgArkPe> m_dummy_rce{ nullptr };
    std::string m_temp_module_name{ "beep" };
    std::unique_ptr<WDbgArkPe> m_temp_module{ nullptr };

    std::string m_struct_name{};
    uint64_t m_expdebuggerworkitem_offset = 0ULL;
    uint64_t m_workerroutine_original_offset = 0ULL;
    uint64_t m_workerroutine_original = 0ULL;
    uint64_t m_workerroutine_parameter_original_offset = 0ULL;
    uint64_t m_workerroutine_parameter_original = 0ULL;
    uint64_t m_expdebuggerwork_offset = 0ULL;
    unique_buf_size m_global_data{};

    bool m_code_section_used = false;
    uint64_t m_code_section_start = 0ULL;
    unique_buf_size m_code_section{};

    bool m_data_section_used = false;
    uint64_t m_data_section_start = 0ULL;
    unique_buf_size m_data_section{};

    command_info m_command_info = {
        { "cpuid", { "CpuidWorker", "%s : EAX = 0x%X, EBX = 0x%X, ECX = 0x%X, EDX = 0x%X\n" } }
    };

    shellcode_info m_shellcode_info{};

    //////////////////////////////////////////////////////////////////////////
    // output streams
    //////////////////////////////////////////////////////////////////////////
    std::stringstream err{};
};

}   // namespace wa

#endif  // WDRCE_HPP_
