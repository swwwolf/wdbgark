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

#include "wdrce.hpp"

#include <string>
#include <memory>
#include <utility>

#include "resources.hpp"
#include "manipulators.hpp"
#include "util.hpp"

namespace wa {

//////////////////////////////////////////////////////////////////////////
// don't include resource.h
//////////////////////////////////////////////////////////////////////////
#define IDR_RT_RCDATA3 107
#define IDR_RT_RCDATA4 108

//////////////////////////////////////////////////////////////////////////
WDbgArkRce::WDbgArkRce(const std::shared_ptr<WDbgArkSymbolsBase> &symbols_base,
                       const std::shared_ptr<WDbgArkDummyPdb> &dummy_pdb,
                       const std::shared_ptr<WDbgArkSymCache> &sym_cache) : m_symbols_base(symbols_base),
                                                                            m_dummy_pdb(dummy_pdb),
                                                                            m_sym_cache(sym_cache) {
    if ( FAILED(g_Ext->m_Client->QueryInterface(__uuidof(IDebugDataSpaces), reinterpret_cast<void**>(&m_Data))) ) {
        m_Data.Set(nullptr);
        err << wa::showminus << __FUNCTION__ << ": Failed to initialize interface" << endlerr;
    }
}
//////////////////////////////////////////////////////////////////////////
WDbgArkRce::WDbgArkRce(const std::shared_ptr<WDbgArkSymbolsBase> &symbols_base,
                       const std::shared_ptr<WDbgArkDummyPdb> &dummy_pdb,
                       const std::shared_ptr<WDbgArkSymCache> &sym_cache,
                       const std::string &temp_module_name) : WDbgArkRce(symbols_base, dummy_pdb, sym_cache) {
    m_temp_module_name = temp_module_name;
}
//////////////////////////////////////////////////////////////////////////
WDbgArkRce::~WDbgArkRce() {
    try {
        std::string filename = GetFullPath();
        std::ifstream file(filename);

        if ( file.good() ) {
            file.close();
            std::remove(filename.c_str());
        }
    } catch ( const std::ios_base::failure& ) {}
      catch ( const std::runtime_error& ) {}

    if ( IsInited() ) {
        SetWorkItemState(WinKdWorkerReady);
        UnHookWorkItem();
        RevertTempModule();
    }

    if ( m_Data.IsSet() ) {
        EXT_RELEASE(m_Data);
    }
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::Init() {
    if ( IsInited() ) {
        return true;
    }

    if ( !m_Data.IsSet() ) {
        return false;
    }

    m_inited = InitWdRce();

    return IsInited();
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::ExecuteCpuid(const int function_id, const int subfunction_id) {
    if ( !IsInited() ) {
        return false;
    }

    ExecutePreCommand();

    if ( !SetCpuidParameters(function_id, subfunction_id) ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to set CPUID parameters" << endlerr;
        return false;
    }

    return ExecuteCommand("cpuid");
}
bool WDbgArkRce::ExecuteCopyfile(const std::wstring &path) {
    if ( !IsInited() ) {
        return false;
    }

    if ( path.empty() ) {
        return false;
    }

    ExecutePreCommand();

    if ( !SetCopyfileParameters(path) ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to set CopyFile parameters" << endlerr;
        return false;
    }

    return ExecuteCommand("copyfile");
}
//////////////////////////////////////////////////////////////////////////
// order of init routines is important!!!
bool WDbgArkRce::InitWdRce() {
    if ( !IsLiveKernel() ) {
        return false;
    }

    if ( !InitSymbols() ) {
        return false;
    }

    if ( !InitTempModule() ) {
        return false;
    }

    if ( !InitRceModule() ) {
        return false;
    }

    return true;
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::InitSymbols() {
    auto result = m_sym_cache->GetSymbolOffset("nt!ExpDebuggerWorkItem",
                                               true,
                                               &m_debugger_info.expdebuggerworkitem_offset);

    if ( !result ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to locate ExpDebuggerWorkItem" << endlerr;
        return false;
    }

    result = m_sym_cache->GetSymbolOffset("nt!ExpDebuggerWork", true, &m_debugger_info.expdebuggerwork_offset);

    if ( !result ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to locate ExpDebuggerWork" << endlerr;
        return false;
    }

    return InitGlobalData();
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::InitGlobalData() {
    m_struct_name = m_dummy_pdb->GetShortName() + "!_WORKITEM_GLOBAL_DATA";
    size_t global_data_size = GetTypeSize(m_struct_name.c_str());

    if ( !global_data_size ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to locate _WORKITEM_GLOBAL_DATA" << endlerr;
        return false;
    }

    m_global_data = { std::make_unique<uint8_t[]>(global_data_size), global_data_size };

    auto result = FillGlobalData(m_struct_name,
                                 "ExpDebuggerWorkItem",
                                 &m_debugger_info.expdebuggerworkitem_offset,
                                 g_Ext->m_PtrSize);

    if ( !result ) {
        err << wa::showminus << __FUNCTION__ << ": FillGlobalData for ExpDebuggerWorkItem failed" << endlerr;
        return false;
    }

    ExtRemoteTyped expdebuggerworkitem("nt!_WORK_QUEUE_ITEM",
                                       m_debugger_info.expdebuggerworkitem_offset,
                                       false,
                                       nullptr,
                                       nullptr);

    size_t type_size = expdebuggerworkitem.GetTypeSize();
    unique_buf temp_buffer = std::make_unique<uint8_t[]>(type_size);
    expdebuggerworkitem.ReadBuffer(temp_buffer.get(), static_cast<uint32_t>(type_size));

    result = FillGlobalData(m_struct_name, "ExpDebuggerWorkItemOriginal", temp_buffer.get(), type_size);

    if ( !result ) {
        err << wa::showminus << __FUNCTION__ << ": FillGlobalData for ExpDebuggerWorkItemOriginal failed" << endlerr;
        return false;
    }

    result = FillGlobalData(m_struct_name,
                            "ExpDebuggerWork",
                            &m_debugger_info.expdebuggerwork_offset,
                            g_Ext->m_PtrSize);

    if ( !result ) {
        err << wa::showminus << __FUNCTION__ << ": FillGlobalData for ExpDebuggerWork failed" << endlerr;
        return false;
    }

    return InitGlobalDataImports();
}
bool WDbgArkRce::InitGlobalDataImports() {
    for ( const auto [import, placeholder] : m_imports ) {
        if ( !InitGlobalDataImport(import, placeholder) ) {
            return false;
        }
    }

    return true;
}
bool WDbgArkRce::InitGlobalDataImport(const std::string &import_name, const std::string &placeholder_name) {
    uint64_t offset = 0ULL;

    if ( !m_sym_cache->GetSymbolOffset(import_name.c_str(), true, &offset) ) {
        err << wa::showminus << __FUNCTION__ << ": " << import_name << " not found" << endlerr;
        return false;
    }

    const auto result = FillGlobalData(m_struct_name, placeholder_name, &offset, g_Ext->m_PtrSize);

    if ( !result ) {
        err << wa::showminus << __FUNCTION__ << ": FillGlobalData for " << placeholder_name << " failed" << endlerr;
        return false;
    }

    return true;
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::FillGlobalData(const std::string &struct_name,
                                const std::string &field_name,
                                const void* buffer,
                                size_t size) {
    uint32_t offset = 0;
    const auto result = GetFieldOffset(struct_name.c_str(), field_name.c_str(), reinterpret_cast<PULONG>(&offset));

    if ( result ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to locate " << struct_name << "." << field_name << endlerr;
        return false;
    }

    const auto& [global_buffer, global_size] = m_global_data;
    std::memcpy(reinterpret_cast<char*>(global_buffer.get()) + static_cast<ptrdiff_t>(offset), buffer, size);
    return true;
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::InitTempModule() {
    uint64_t address = 0ULL;
    auto result = g_Ext->m_Symbols3->GetModuleByModuleName2(m_temp_module_name.c_str(),
                                                            0UL,
                                                            DEBUG_GETMOD_NO_UNLOADED_MODULES,
                                                            nullptr,
                                                            &address);

    if ( FAILED(result) ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to locate TEMP module" << endlerr;
        return false;
    }

    uint64_t base = 0;
    uint32_t size = 0;

    result = m_symbols_base->GetModuleStartSize(address, &base, &size);

    if ( FAILED(result) ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to get TEMP module base and start" << endlerr;
        return false;
    }

    auto temp_module = std::make_unique<WDbgArkPe>(base, size, m_symbols_base);

    if ( !temp_module->IsValid() ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to map TEMP module" << endlerr;
        return false;
    }

    // init code placeholder
    if ( !InitTempModuleCodeSection(temp_module) ) {
        err << wa::showminus << __FUNCTION__ << ": InitTempModuleCodeSection failed" << endlerr;
        return false;
    }

    // init data placeholder
    if ( !InitTempModuleDataSection(temp_module) ) {
        err << wa::showminus << __FUNCTION__ << ": InitTempModuleDataSection failed" << endlerr;
        return false;
    }

    return true;
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::InitTempModuleCodeSection(const std::unique_ptr<WDbgArkPe> &temp_module) {
    IMAGE_SECTION_HEADER header = { 0 };
    auto result = temp_module->GetImageSection(".text", &header);

    if ( !result || !header.VirtualAddress || !header.Misc.VirtualSize ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to find .text section" << endlerr;
        return false;
    }

    m_code_section_start = reinterpret_cast<uint64_t>(reinterpret_cast<char*>(temp_module->GetReadMemoryBase()) + \
                                                      static_cast<ptrdiff_t>(header.VirtualAddress));

    size_t code_section_size = static_cast<size_t>(header.Misc.VirtualSize);
    auto code_section_bytes = std::make_unique<uint8_t[]>(code_section_size);

    auto code_section_start = reinterpret_cast<const void*>(reinterpret_cast<char*>(temp_module->GetBase()) + \
                                                            static_cast<ptrdiff_t>(header.VirtualAddress));

    std::memcpy(code_section_bytes.get(), code_section_start, code_section_size);
    m_code_section = { std::move(code_section_bytes), code_section_size };

    return true;
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::ReInitTempModuleCodeSection(const uint64_t address, const size_t buffer_size) {
    auto code_section_bytes = std::make_unique<uint8_t[]>(buffer_size);

    if ( FAILED(ReadVirtualUncached(address, buffer_size, code_section_bytes.get())) ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to read code section" << endlerr;
        return false;
    }

    m_code_section_start = address;

    auto& [code_buffer, code_size] = m_code_section;
    code_buffer.reset(nullptr);
    m_code_section = { std::move(code_section_bytes), buffer_size };

    return true;
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::InitTempModuleDataSection(const std::unique_ptr<WDbgArkPe> &temp_module) {
    IMAGE_SECTION_HEADER* first_header = nullptr;

    if ( !temp_module->GetImageFirstSection(&first_header) ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to reserve data section" << endlerr;
        return false;
    }

    ptrdiff_t start = 0;
    size_t size = static_cast<size_t>(first_header->Misc.VirtualSize);

    m_data_section_start = reinterpret_cast<uint64_t>(reinterpret_cast<char*>(temp_module->GetReadMemoryBase()) +
                                                      start);

    auto data_section_bytes = std::make_unique<uint8_t[]>(size);
    auto data_section_start = reinterpret_cast<const void*>(reinterpret_cast<char*>(temp_module->GetBase()) + start);

    std::memcpy(data_section_bytes.get(), data_section_start, size);
    m_data_section = { std::move(data_section_bytes), size };

    return true;
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::ReInitTempModuleDataSection(const uint64_t address, const size_t buffer_size) {
    auto data_section_bytes = std::make_unique<uint8_t[]>(buffer_size);

    if ( FAILED(ReadVirtualUncached(address, buffer_size, data_section_bytes.get())) ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to read data section" << endlerr;
        return false;
    }

    m_data_section_start = address;

    auto& [data_buffer, data_size] = m_data_section;
    data_buffer.reset(nullptr);
    m_data_section = { std::move(data_section_bytes), buffer_size };

    return true;
}
//////////////////////////////////////////////////////////////////////////
ExtRemoteTyped WDbgArkRce::GetDataSectionTyped() {
    return ExtRemoteTyped(m_struct_name.c_str(), m_data_section_start, false, nullptr, nullptr);
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::InitRceModule() {
    char* resource_name = nullptr;

    if ( g_Ext->IsCurMachine64() ) {
        resource_name = MAKEINTRESOURCE(IDR_RT_RCDATA4);
    } else {
        resource_name = MAKEINTRESOURCE(IDR_RT_RCDATA3);
    }

    std::string dummy_rce_name{ "dummyrce_" + std::to_string(GetCurrentProcessId()) + ".sys" };
    auto res_helper = std::make_unique<WDbgArkResHelper>();

    if ( !res_helper->DropResource(resource_name, "RT_RCDATA", dummy_rce_name) ) {
        err << wa::showminus << __FUNCTION__ << ": DropResource failed" << endlerr;
        return false;
    }

    m_dummy_rce_full_path = res_helper->GetDropPath() + dummy_rce_name;
    auto dummy_rce = std::make_unique<WDbgArkPe>(string_to_wstring(GetFullPath()), m_symbols_base);

    if ( !dummy_rce->IsValid() ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to map RCE module" << endlerr;
        return false;
    }

    return InitRceShellcodes(dummy_rce);
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::InitRceShellcodes(const std::unique_ptr<WDbgArkPe> &dummy_rce) {
    for ( const auto [command_name, cmd_info] : m_command_info ) {
        auto function_name = m_dummy_pdb->GetShortName() + "!" + cmd_info.rce_function_name;

        const auto result = InitRceShellcode(function_name, command_name, dummy_rce);

        if ( !result ) {
            err << wa::showminus << __FUNCTION__ << ": InitRceShellcode failed for " << function_name << endlerr;
            return false;
        }
    }

    return true;
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::InitRceShellcode(const std::string &function_name,
                                  const std::string &command_name,
                                  const std::unique_ptr<WDbgArkPe> &dummy_rce) {
    uint64_t start_offset = 0ULL;
    uint64_t end_offset = 0ULL;

    const auto result = m_symbols_base->GetFunctionInformation(function_name, &start_offset, &end_offset);

    if ( FAILED(result) ) {
        err << wa::showminus << __FUNCTION__ << ": GetFunctionInformation failed for " << function_name << endlerr;
        return false;
    }

    size_t size = static_cast<size_t>(end_offset - start_offset);
    auto buffer = std::make_unique<uint8_t[]>(size);
    
    std::memcpy(buffer.get(),
                reinterpret_cast<char*>(dummy_rce->GetBase()) + static_cast<ptrdiff_t>(start_offset),
                size);

    unique_buf_size code{ std::move(buffer), size };
    m_shellcode_info[command_name] = std::move(code);

    return true;
}
//////////////////////////////////////////////////////////////////////////
void WDbgArkRce::ExecutePreCommand() {
    RelocateCodeAndData();
    m_data_section_need_size = GetDataSectionTyped().GetFieldOffset("p");
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::RelocateCodeAndData() {
    if ( m_relocated ) {
        return true;
    }

    if ( !m_code_section_used || !m_data_section_used ) {
        return true;
    }

    uint64_t buffer_code = 0ULL;
    auto result = GetOption("BufferCode", g_Ext->m_PtrSize, &buffer_code);

    if ( !result || !buffer_code ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to get BufferCode" << endlerr;
        return false;
    }

    result = NormalizeAddress(buffer_code, &buffer_code);

    if ( !result ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to normalize BufferCode" << endlerr;
        return false;
    }

    result = SetOption("BufferCode", &buffer_code, g_Ext->m_PtrSize);

    if ( !result ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to set BufferCode" << endlerr;
        return false;
    }

    size_t buffer_code_size = 0;
    result = GetOption("BufferCodeSize", sizeof(buffer_code_size), &buffer_code_size);

    if ( !result || !buffer_code_size ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to get BufferCodeSize" << endlerr;
        return false;
    }

    result = SetOption("BufferCodeSize", &buffer_code_size, sizeof(buffer_code_size));

    if ( !result ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to set BufferCodeSize" << endlerr;
        return false;
    }

    uint64_t buffer_data = 0ULL;
    result = GetOption("BufferData", g_Ext->m_PtrSize, &buffer_data);

    if ( !result || !buffer_data ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to get BufferData" << endlerr;
        return false;
    }

    result = NormalizeAddress(buffer_data, &buffer_data);

    if ( !result ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to normalize BufferData" << endlerr;
        return false;
    }

    result = SetOption("BufferData", &buffer_data, g_Ext->m_PtrSize);

    if ( !result ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to set BufferData" << endlerr;
        return false;
    }

    size_t buffer_data_size = 0;
    result = GetOption("BufferDataSize", sizeof(buffer_data_size), &buffer_data_size);

    if ( !result || !buffer_data_size ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to get BufferDataSize" << endlerr;
        return false;
    }

    result = SetOption("BufferDataSize", &buffer_data_size, sizeof(buffer_data_size));

    if ( !result ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to set BufferDataSize" << endlerr;
        return false;
    }

    RevertTempModule();

    result = ReInitTempModuleCodeSection(buffer_code, buffer_code_size);

    if ( !result ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to re-init code section" << endlerr;
        return false;
    }

    result = ReInitTempModuleDataSection(buffer_data, buffer_data_size);

    if ( !result ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to re-init data section" << endlerr;
        return false;
    }

    m_relocated = true;
    return true;
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::ExecuteCommand(const std::string &command_name) {
    const auto& command = m_command_info[command_name];
    const auto& shellcode = m_shellcode_info[command_name];

    if ( !SetFunction(command.rce_function_name) ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to set function name" << endlerr;
        return false;
    }

    if ( !SetOutput(command.output) ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to set output" << endlerr;
        return false;
    }

    if ( !CheckWorkItemState() ) {
        err << wa::showminus << __FUNCTION__ << ": Invalid work item state" << endlerr;
        return false;
    }

    if ( !WriteGlobalData(m_global_data) ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to write global data" << endlerr;
        return false;
    }

    if ( !WriteCodeData(shellcode) ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to write code data" << endlerr;
        return false;
    }

    if ( !HookWorkItem() ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to hook work item" << endlerr;
        return false;
    }

    if ( !SetWorkItemState(WinKdWorkerStart) ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to set work item state" << endlerr;
        return false;
    }

    return true;
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::SetFunction(const std::string &function_name) {
    return SetPrintOption(function_name, "Print.Function");
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::SetOutput(const std::string &output) {
    return SetPrintOption(output, "Print.Output");
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::SetCpuidParameters(const int function_id, const int subfunction_id) {
    if ( !SetOption("p.CpuidEntry.function_id", &function_id, sizeof(function_id)) ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to set function_id" << endlerr;
        return false;
    }

    if ( !SetOption("p.CpuidEntry.subfunction_id", &subfunction_id, sizeof(subfunction_id)) ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to set subfunction_id" << endlerr;
        return false;
    }

    return true;
}
bool WDbgArkRce::SetCopyfileParameters(const std::wstring &path) {
    if ( !SetOption("p.CopyfileEntry.file_path", path.c_str(), path.size() * sizeof(wchar_t), sizeof(wchar_t)) ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to set file_path" << endlerr;
        return false;
    }

    return true;
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::SetPrintOption(const std::string &option, const std::string &field_name) {
    return SetOption(field_name, option.c_str(), option.size(), sizeof(char));
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::SetOption(const std::string &field_name,
                           const void* buffer,
                           const size_t buffer_size,
                           const size_t reserved) {
    auto data_section_typed = GetDataSectionTyped();
    size_t size = data_section_typed.Field(field_name.c_str()).GetTypeSize();
    auto buffer_size_reserved = buffer_size + reserved;

    if ( buffer_size_reserved > size ) {
        err << wa::showminus << __FUNCTION__ << ": Invalid size" << endlerr;
        return false;
    }

    std::string p("p.");

    if ( field_name.compare(0, p.size(), p) == 0 ) {
        m_data_section_need_size += buffer_size_reserved;
    }

    auto offset = data_section_typed.GetFieldOffset(field_name.c_str());
    const auto& [global_buffer, global_size] = m_global_data;
    auto ptr = reinterpret_cast<char*>(global_buffer.get()) + static_cast<ptrdiff_t>(offset);

    std::memset(ptr, 0, size);
    std::memcpy(ptr, buffer, buffer_size);

    return true;
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::GetOption(const std::string &field_name, const size_t buffer_size, void* buffer) {
    auto data_section_typed = GetDataSectionTyped();
    size_t size = data_section_typed.Field(field_name.c_str()).GetTypeSize();

    if ( buffer_size < size ) {
        err << wa::showminus << __FUNCTION__ << ": Invalid size" << endlerr;
        return false;
    }

    auto offset = data_section_typed.GetFieldOffset(field_name.c_str());
    auto ptr = reinterpret_cast<uint64_t>(reinterpret_cast<char*>(m_data_section_start) +
                                          static_cast<ptrdiff_t>(offset));

    return SUCCEEDED(ReadVirtualUncached(ptr, buffer_size, buffer));
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::WriteGlobalData(const unique_buf_size &data) {
    const auto& [buffer, size] = data;

    if ( m_data_section_need_size > size ) {
        return false;
    }

    if ( SUCCEEDED(WriteVirtualUncached(m_data_section_start, buffer.get(), m_data_section_need_size)) ) {
        m_data_section_used = true;
        return true;
    }

    return false;
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::WriteCodeData(const unique_buf_size &code) {
    const auto& [buffer, size] = code;
    const auto& [buffer_code, buffer_size] = m_code_section;

    if ( size > buffer_size ) {
        return false;
    }

    if ( SUCCEEDED(WriteVirtualUncached(m_code_section_start, code)) ) {
        m_code_section_used = true;
        return true;
    }

    return false;
}
//////////////////////////////////////////////////////////////////////////
HRESULT WDbgArkRce::WriteVirtualUncached(const uint64_t address, const unique_buf_size &buffer) {
    const auto& [buffer_write, size] = buffer;
    return WriteVirtualUncached(address, buffer_write.get(), size);
}
//////////////////////////////////////////////////////////////////////////
HRESULT WDbgArkRce::WriteVirtualUncached(const uint64_t address, const void* buffer, const size_t buffer_size) {
    ULONG write_size = 0;
    const auto result = m_Data->WriteVirtualUncached(address,
                                                     const_cast<PVOID>(buffer),
                                                     static_cast<ULONG>(buffer_size),
                                                     &write_size);

    if ( SUCCEEDED(result) && buffer_size != static_cast<size_t>(write_size) ) {
        return E_FAIL;
    }

    return result;
}
//////////////////////////////////////////////////////////////////////////
HRESULT WDbgArkRce::ReadVirtualUncached(const uint64_t address, const size_t buffer_size, void* buffer) {
    ULONG read_size = 0;
    const auto result = m_Data->ReadVirtualUncached(address, buffer, static_cast<ULONG>(buffer_size), &read_size);

    if ( SUCCEEDED(result) && buffer_size != static_cast<size_t>(read_size) ) {
        return E_FAIL;
    }

    return result;
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::HookWorkItem() {
    auto result = HookWorkItemRoutine();

    if ( !result ) {
        err << wa::showminus << __FUNCTION__ << ": Failed to hook WorkerRoutine" << endlerr;
        return false;
    }

    result = HookWorkItemParameter();

    if ( !result ) {
        err << wa::showminus << __FUNCTION__ << ": Failed to hook Parameter" << endlerr;
        return false;
    }

    return true;
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::HookWorkItemRoutine() {
    ExtRemoteTyped expdebuggerworkitem("nt!_WORK_QUEUE_ITEM",
                                       m_debugger_info.expdebuggerworkitem_offset,
                                       false,
                                       nullptr,
                                       nullptr);

    auto routine = expdebuggerworkitem.Field("WorkerRoutine");
    m_debugger_info.workerroutine_original_offset = routine.m_Offset;
    m_debugger_info.workerroutine_original = routine.GetPtr();

    const auto result = WriteVirtualUncached(m_debugger_info.workerroutine_original_offset,
                                             &m_code_section_start,
                                             g_Ext->m_PtrSize);

    if ( FAILED(result) ) {
        return false;
    }

    return true;
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::HookWorkItemParameter() {
    ExtRemoteTyped expdebuggerworkitem("nt!_WORK_QUEUE_ITEM",
                                       m_debugger_info.expdebuggerworkitem_offset,
                                       false,
                                       nullptr,
                                       nullptr);

    auto parameter = expdebuggerworkitem.Field("Parameter");
    m_debugger_info.workerroutine_parameter_original_offset = parameter.m_Offset;
    m_debugger_info.workerroutine_parameter_original = parameter.GetPtr();

    const auto result = WriteVirtualUncached(m_debugger_info.workerroutine_parameter_original_offset,
                                             &m_data_section_start,
                                             g_Ext->m_PtrSize);

    if ( FAILED(result) ) {
        return false;
    }

    return true;
}
//////////////////////////////////////////////////////////////////////////
void WDbgArkRce::UnHookWorkItemParameter() {
    uint64_t address = 0ULL;
    auto result = ReadVirtualUncached(m_debugger_info.workerroutine_parameter_original_offset,
                                      g_Ext->m_PtrSize,
                                      &address);

    if ( SUCCEEDED(result) && address != m_debugger_info.workerroutine_parameter_original ) {
        result = WriteVirtualUncached(m_debugger_info.workerroutine_parameter_original_offset,
                                      &m_debugger_info.workerroutine_parameter_original,
                                      g_Ext->m_PtrSize);
    }
}
//////////////////////////////////////////////////////////////////////////
void WDbgArkRce::UnHookWorkItemRoutine() {
    uint64_t address = 0ULL;
    auto result = ReadVirtualUncached(m_debugger_info.workerroutine_original_offset, g_Ext->m_PtrSize, &address);

    if ( SUCCEEDED(result) && address != m_debugger_info.workerroutine_original ) {
        result = WriteVirtualUncached(m_debugger_info.workerroutine_original_offset,
                                      &m_debugger_info.workerroutine_original,
                                      g_Ext->m_PtrSize);
    }
}
//////////////////////////////////////////////////////////////////////////
void WDbgArkRce::UnHookWorkItem() {
    UnHookWorkItemParameter();
    UnHookWorkItemRoutine();
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::SetWorkItemState(const WINKD_WORKER_STATE state) {
    const auto result = WriteVirtualUncached(m_debugger_info.expdebuggerwork_offset, &state, sizeof(LONG));

    if ( FAILED(result) ) {
        return false;
    }

    return true;
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::CheckWorkItemState() {
    WINKD_WORKER_STATE state;
    const auto result = ReadVirtualUncached(m_debugger_info.expdebuggerwork_offset, sizeof(LONG), &state);

    if ( FAILED(result) ) {
        return false;
    }

    return (state == WinKdWorkerReady);
}
//////////////////////////////////////////////////////////////////////////
void WDbgArkRce::RevertTempModule() {
    if ( m_code_section_used ) {
        WriteCodeData(m_code_section);
        m_code_section_used = false;
    }

    if ( m_data_section_used ) {
        WriteGlobalData(m_data_section);
        m_data_section_used = false;
    }
}
//////////////////////////////////////////////////////////////////////////

}   // namespace wa
