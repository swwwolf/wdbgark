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
#include <vector>

#include "symbols.hpp"
#include "dummypdb.hpp"
#include "pe.hpp"
#include "strings.hpp"
#include "symcache.hpp"

namespace wa {

class WDbgArkRce {
 public:
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
    bool ExecuteCopyfile(const std::wstring &path);

 private:
    using unique_buf = std::unique_ptr<uint8_t[]>;
    using unique_buf_size = std::pair<unique_buf, size_t>;
    using import = std::pair<std::string, std::string>;     // import name : placeholder name

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

    std::string GetFullPath() const { return m_dummy_rce_full_path; }

    bool InitWdRce();
    bool InitSymbols();
    bool InitGlobalData();
    bool InitGlobalDataImports();
    bool InitGlobalDataImport(const std::string &import_name, const std::string &placeholder_name);
    bool FillGlobalData(const std::string &struct_name,
                        const std::string &field_name,
                        const void* buffer,
                        const size_t size);
    bool InitTempModule();
    bool InitTempModuleCodeSection(const std::unique_ptr<WDbgArkPe> &temp_module);
    bool ReInitTempModuleCodeSection(const uint64_t address, const size_t buffer_size);
    bool InitTempModuleDataSection(const std::unique_ptr<WDbgArkPe> &temp_module);
    bool ReInitTempModuleDataSection(const uint64_t address, const size_t buffer_size);
    ExtRemoteTyped GetDataSectionTyped();
    bool InitRceModule();
    bool InitRceShellcodes(const std::unique_ptr<WDbgArkPe> &dummy_rce);
    bool InitRceShellcode(const std::string &function_name,
                          const std::string &command_name,
                          const std::unique_ptr<WDbgArkPe> &dummy_rce);

    void ExecutePreCommand();
    bool RelocateCodeAndData();
    bool ExecuteCommand(const std::string &command_name);

    bool SetFunction(const std::string &function_name);
    bool SetOutput(const std::string &output);
    bool SetCpuidParameters(const int function_id, const int subfunction_id = 0);
    bool SetCopyfileParameters(const std::wstring &path);
    bool SetPrintOption(const std::string &option, const std::string &field_name);
    bool SetOption(const std::string &field_name,
                   const void* buffer,
                   const size_t buffer_size,
                   const size_t reserved = 0);
    bool GetOption(const std::string &field_name, const size_t buffer_size, void* buffer);
    bool WriteGlobalData(const unique_buf_size &data);
    bool WriteCodeData(const unique_buf_size &code);
    HRESULT WriteVirtualUncached(const uint64_t address, const unique_buf_size &buffer);
    HRESULT WriteVirtualUncached(const uint64_t address, const void* buffer, const size_t buffer_size);
    HRESULT ReadVirtualUncached(const uint64_t address, const size_t buffer_size, void* buffer);
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
    bool m_relocated = false;
    std::shared_ptr<WDbgArkSymbolsBase> m_symbols_base{ nullptr };
    std::shared_ptr<WDbgArkDummyPdb> m_dummy_pdb{ nullptr };
    std::shared_ptr<WDbgArkSymCache> m_sym_cache{ nullptr };
    ExtCheckedPointer<IDebugDataSpaces> m_Data{ "The extension did not initialize properly." };

    std::string m_dummy_rce_full_path{};
    std::string m_temp_module_name{ "beep" };

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
    size_t m_data_section_need_size = 0;

    command_info m_command_info = {
        { "cpuid", { "CpuidWorker",
                     "%s : EAX = 0x%X, EBX = 0x%X, ECX = 0x%X, EDX = 0x%X. Hit \'go\' to continue.\n" } },
        { "copyfile", { "CopyfileWorker",
                        "%s : Buffer = 0x%p, Size = 0x%p. Hit \'go\' to continue and free the buffer.\n" } }
    };

    std::vector<import> m_imports = {
        { "nt!DbgPrint", "Iat.fnt_DbgPrint" },
        { "nt!DbgBreakPointWithStatus", "Iat.fnt_DbgBreakPointWithStatus" },
        { "nt!RtlInitUnicodeString", "Iat.fnt_RtlInitUnicodeString" },
        { "nt!IoCreateFile", "Iat.fnt_IoCreateFile" },
        { "nt!ZwClose", "Iat.fnt_ZwClose" },
        { "nt!ZwQueryInformationFile", "Iat.fnt_ZwQueryInformationFile" },
        { "nt!ExAllocatePoolWithTag", "Iat.fnt_ExAllocatePoolWithTag" },
        { "nt!ExFreePoolWithTag", "Iat.fnt_ExFreePoolWithTag" },
        { "nt!IoAllocateMdl", "Iat.fnt_IoAllocateMdl" },
        { "nt!IoFreeMdl", "Iat.fnt_IoFreeMdl" },
        { "nt!MmBuildMdlForNonPagedPool", "Iat.fnt_MmBuildMdlForNonPagedPool" },
        { "nt!MmProtectMdlSystemAddress", "Iat.fnt_MmProtectMdlSystemAddress" },
        { "nt!MmMapLockedPagesSpecifyCache", "Iat.fnt_MmMapLockedPagesSpecifyCache" },
        { "nt!MmUnmapLockedPages", "Iat.fnt_MmUnmapLockedPages" },
        { "nt!ZwCreateSection", "Iat.fnt_ZwCreateSection" },
        { "nt!ZwMapViewOfSection", "Iat.fnt_ZwMapViewOfSection" },
        { "nt!ZwUnmapViewOfSection", "Iat.fnt_ZwUnmapViewOfSection" },
        { "nt!memset", "Iat.fnt_memset" },
        { "nt!memcpy", "Iat.fnt_memcpy" }
    };

    shellcode_info m_shellcode_info{};

    //////////////////////////////////////////////////////////////////////////
    // output streams
    //////////////////////////////////////////////////////////////////////////
    std::stringstream err{};
};

}   // namespace wa

#endif  // WDRCE_HPP_
