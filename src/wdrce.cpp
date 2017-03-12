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
    auto result = g_Ext->m_Client->QueryInterface(__uuidof(IDebugDataSpaces), reinterpret_cast<void**>(&m_data_iface));

    if ( FAILED(result) ) {
        m_data_iface.Set(nullptr);
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
    std::string filename = GetFullPath();
    std::ifstream file(filename);

    if ( file.good() ) {
        file.close();
        std::remove(filename.c_str());
    }

    if ( IsInited() ) {
        SetWorkItemState(WinKdWorkerReady);
        UnHookWorkItem();
        RevertTempModule();
    }

    if ( m_data_iface.IsSet() ) {
        EXT_RELEASE(m_data_iface);
    }
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::Init() {
    if ( IsInited() ) {
        return true;
    }

    if ( !m_data_iface.IsSet() ) {
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

    const std::string command_name = "cpuid";

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

    if ( !SetCpuidParameters(function_id, subfunction_id) ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to set CPUID parameters" << endlerr;
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
    auto result = m_sym_cache->GetSymbolOffset("nt!ExpDebuggerWorkItem", true, &m_expdebuggerworkitem_offset);

    if ( !result ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to locate ExpDebuggerWorkItem" << endlerr;
        return false;
    }

    result = m_sym_cache->GetSymbolOffset("nt!ExpDebuggerWork", true, &m_expdebuggerwork_offset);

    if ( !result ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to locate ExpDebuggerWork" << endlerr;
        return false;
    }

    return InitGlobalData();
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::InitGlobalData() {
    m_struct_name = m_dummy_pdb->GetShortName() + "!_WORKITEM_GLOBAL_DATA";
    auto global_data_size = GetTypeSize(m_struct_name.c_str());

    if ( !global_data_size ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to locate _WORKITEM_GLOBAL_DATA" << endlerr;
        return false;
    }

    m_global_data = { std::make_unique<uint8_t[]>(global_data_size), global_data_size };

    auto result = FillGlobalData(m_struct_name, "ExpDebuggerWorkItem", &m_expdebuggerworkitem_offset, g_Ext->m_PtrSize);

    if ( !result ) {
        err << wa::showminus << __FUNCTION__ << ": FillGlobalData for ExpDebuggerWorkItem failed" << endlerr;
        return false;
    }

    ExtRemoteTyped expdebuggerworkitem("nt!_WORK_QUEUE_ITEM", m_expdebuggerworkitem_offset, false, nullptr, nullptr);

    auto type_size = expdebuggerworkitem.GetTypeSize();
    unique_buf temp_buffer = std::make_unique<uint8_t[]>(type_size);
    expdebuggerworkitem.ReadBuffer(temp_buffer.get(), type_size);
    result = FillGlobalData(m_struct_name, "ExpDebuggerWorkItemOriginal", temp_buffer.get(), type_size);

    if ( !result ) {
        err << wa::showminus << __FUNCTION__ << ": FillGlobalData for ExpDebuggerWorkItemOriginal failed" << endlerr;
        return false;
    }

    result = FillGlobalData(m_struct_name, "ExpDebuggerWork", &m_expdebuggerwork_offset, g_Ext->m_PtrSize);

    if ( !result ) {
        err << wa::showminus << __FUNCTION__ << ": FillGlobalData for ExpDebuggerWork failed" << endlerr;
        return false;
    }

    uint64_t iat_offset = 0ULL;

    if ( !m_sym_cache->GetSymbolOffset("nt!DbgPrint", true, &iat_offset) ) {
        err << wa::showminus << __FUNCTION__ << ": nt!DbgPrint not found" << endlerr;
        return false;
    }

    result = FillGlobalData(m_struct_name, "Iat.fnt_DbgPrint", &iat_offset, g_Ext->m_PtrSize);

    if ( !result ) {
        err << wa::showminus << __FUNCTION__ << ": FillGlobalData for fnt_DbgPrint failed" << endlerr;
        return false;
    }

    if ( !m_sym_cache->GetSymbolOffset("nt!DbgBreakPointWithStatus", true, &iat_offset) ) {
        err << wa::showminus << __FUNCTION__ << ": nt!DbgBreakPointWithStatus not found" << endlerr;
        return false;
    }

    result = FillGlobalData(m_struct_name, "Iat.fnt_DbgBreakPointWithStatus", &iat_offset, g_Ext->m_PtrSize);

    if ( !result ) {
        err << wa::showminus << __FUNCTION__ << ": FillGlobalData for fnt_DbgBreakPointWithStatus failed" << endlerr;
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
    auto result = GetFieldOffset(struct_name.c_str(), field_name.c_str(), reinterpret_cast<PULONG>(&offset));

    if ( result ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to locate " << struct_name << "." << field_name << endlerr;
        return false;
    }

    std::memcpy(reinterpret_cast<char*>(m_global_data.first.get()) + static_cast<ptrdiff_t>(offset), buffer, size);
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

    m_temp_module = std::make_unique<WDbgArkPe>(base, size, m_symbols_base);

    if ( !m_temp_module->IsValid() ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to map TEMP module" << endlerr;
        return false;
    }

    // init code placeholder
    if ( !InitTempModuleCodeSection() ) {
        err << wa::showminus << __FUNCTION__ << ": InitTempModuleCodeSection failed" << endlerr;
        return false;
    }

    // init data placeholder
    if ( !InitTempModuleDataSection() ) {
        err << wa::showminus << __FUNCTION__ << ": InitTempModuleDataSection failed" << endlerr;
        return false;
    }

    return true;
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::InitTempModuleCodeSection() {
    IMAGE_SECTION_HEADER header = { 0 };
    auto result = m_temp_module->GetImageSection(".text", &header);

    if ( !result || !header.VirtualAddress || !header.Misc.VirtualSize ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to find .text section" << endlerr;
        return false;
    }

    m_code_section_start = reinterpret_cast<uint64_t>(reinterpret_cast<char*>(m_temp_module->GetReadMemoryBase()) + \
                                                      static_cast<ptrdiff_t>(header.VirtualAddress));
    auto code_section_size = header.Misc.VirtualSize;
    auto code_section_bytes = std::make_unique<uint8_t[]>(code_section_size);
    auto code_section_start = reinterpret_cast<const void*>(reinterpret_cast<char*>(m_temp_module->GetBase()) + \
                                                            static_cast<ptrdiff_t>(header.VirtualAddress));

    std::memcpy(code_section_bytes.get(), code_section_start, code_section_size);
    m_code_section = { std::move(code_section_bytes), code_section_size };

    return true;
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::InitTempModuleDataSection() {
    IMAGE_SECTION_HEADER header = { 0 };

    auto result = m_temp_module->GetImageSection(".rdata", &header);

    if ( !result || !header.VirtualAddress || !header.Misc.VirtualSize ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to locate .rdata section" << endlerr;
        return false;
    }

    ptrdiff_t start = 0;
    uint32_t size = 0;

    if ( m_global_data.second > header.Misc.VirtualSize ) {
        IMAGE_SECTION_HEADER* first_header = nullptr;

        if ( !m_temp_module->GetImageFirstSection(&first_header) ) {
            err << wa::showminus << __FUNCTION__ << ": unable to reserve data section" << endlerr;
            return false;
        }

        if ( m_global_data.second > first_header->VirtualAddress ) {
            err << wa::showminus << __FUNCTION__ << ": data section is too small" << endlerr;
            return false;
        }

        start = 0;
        size = first_header->VirtualAddress;
    } else {
        start = static_cast<ptrdiff_t>(header.VirtualAddress);
        size = header.Misc.VirtualSize;
    }

    m_data_section_start = reinterpret_cast<uint64_t>(reinterpret_cast<char*>(m_temp_module->GetReadMemoryBase()) + \
                                                      start);
    auto data_section_bytes = std::make_unique<uint8_t[]>(size);
    auto data_section_start = reinterpret_cast<const void*>(reinterpret_cast<char*>(m_temp_module->GetBase()) + \
                                                            start);

    std::memcpy(data_section_bytes.get(), data_section_start, size);
    m_data_section = { std::move(data_section_bytes), size };

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
    m_dummy_rce = std::make_unique<WDbgArkPe>(string_to_wstring(GetFullPath()), m_symbols_base);

    if ( !m_dummy_rce->IsValid() ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to map RCE module" << endlerr;
        return false;
    }

    return InitRceShellcodes();
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::InitRceShellcodes() {
    for ( const auto& entry : m_command_info ) {
        auto function_name = m_dummy_pdb->GetShortName() + "!" + entry.second.rce_function_name;
        auto command_name = entry.first;

        auto result = InitRceShellcode(function_name, command_name);

        if ( !result ) {
            err << wa::showminus << __FUNCTION__ << ": InitRceShellcode failed for " << function_name << endlerr;
            return false;
        }
    }

    return true;
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::InitRceShellcode(const std::string &function_name, const std::string &command_name) {
    uint64_t start_offset = 0ULL;
    uint64_t end_offset = 0ULL;

    auto result = m_symbols_base->GetFunctionInformation(function_name, &start_offset, &end_offset);

    if ( FAILED(result) ) {
        err << wa::showminus << __FUNCTION__ << ": GetFunctionInformation failed for " << function_name << endlerr;
        return false;
    }

    size_t size = static_cast<size_t>(end_offset - start_offset);

    if ( size > m_code_section.second ) {
        err << wa::showminus << __FUNCTION__ << ": Code length is too big to fit in .text section" << endlerr;
        return false;
    }

    unique_buf_size code{ std::make_unique<uint8_t[]>(size), size };

    std::memcpy(code.first.get(),
                reinterpret_cast<char*>(m_dummy_rce->GetBase()) + static_cast<ptrdiff_t>(start_offset),
                size);

    m_shellcode_info[command_name] = std::move(code);

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
    if ( !SetParameterOption("p.CpuidEntry.function_id", &function_id, sizeof(function_id)) ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to set function_id" << endlerr;
        return false;
    }

    if ( !SetParameterOption("p.CpuidEntry.subfunction_id", &subfunction_id, sizeof(subfunction_id)) ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to set subfunction_id" << endlerr;
        return false;
    }

    return true;
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::SetPrintOption(const std::string &option, const std::string &field_name) {
    auto data_section_typed = GetDataSectionTyped();
    size_t size = data_section_typed.Field(field_name.c_str()).GetTypeSize();

    if ( option.size() >= size ) {
        err << wa::showminus << __FUNCTION__ << ": Invalid size" << endlerr;
        return false;
    }

    auto offset = data_section_typed.GetFieldOffset(field_name.c_str());

    std::memcpy(reinterpret_cast<char*>(m_global_data.first.get()) + static_cast<ptrdiff_t>(offset),
                option.c_str(),
                option.size());

    return true;
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::SetParameterOption(const std::string &field_name, const void* buffer, const size_t buffer_size) {
    auto data_section_typed = GetDataSectionTyped();
    size_t size = data_section_typed.Field(field_name.c_str()).GetTypeSize();

    if ( buffer_size != size ) {
        err << wa::showminus << __FUNCTION__ << ": Invalid size" << endlerr;
        return false;
    }

    auto offset = data_section_typed.GetFieldOffset(field_name.c_str());

    std::memcpy(reinterpret_cast<char*>(m_global_data.first.get()) + static_cast<ptrdiff_t>(offset),
                buffer,
                buffer_size);

    return true;
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::WriteGlobalData(const unique_buf_size &data) {
    auto result = WriteVirtualUncached(m_data_section_start, data);

    if ( SUCCEEDED(result) ) {
        m_data_section_used = true;
        return true;
    }

    return false;
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::WriteCodeData(const unique_buf_size &code) {
    auto result = WriteVirtualUncached(m_code_section_start, code);

    if ( SUCCEEDED(result) ) {
        m_code_section_used = true;
        return true;
    }

    return false;
}
//////////////////////////////////////////////////////////////////////////
HRESULT WDbgArkRce::WriteVirtualUncached(const uint64_t address, const unique_buf_size &buffer) {
    return WriteVirtualUncached(address, buffer.first.get(), buffer.second);
}
//////////////////////////////////////////////////////////////////////////
HRESULT WDbgArkRce::WriteVirtualUncached(const uint64_t address, const void* buffer, const size_t buffer_size) {
    uint32_t write_size = 0;
    auto result = m_data_iface->WriteVirtualUncached(address,
                                                     const_cast<PVOID>(buffer),
                                                     static_cast<ULONG>(buffer_size),
                                                     reinterpret_cast<PULONG>(&write_size));

    if ( SUCCEEDED(result) && buffer_size != write_size ) {
        return E_FAIL;
    }

    return result;
}
//////////////////////////////////////////////////////////////////////////
HRESULT WDbgArkRce::ReadVirtualUncached(const uint64_t address, const void* buffer, const size_t buffer_size) {
    uint32_t read_size = 0;
    auto result = m_data_iface->ReadVirtualUncached(address,
                                                    const_cast<PVOID>(buffer),
                                                    static_cast<ULONG>(buffer_size),
                                                    reinterpret_cast<PULONG>(&read_size));

    if ( SUCCEEDED(result) && buffer_size != read_size ) {
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
    ExtRemoteTyped expdebuggerworkitem("nt!_WORK_QUEUE_ITEM", m_expdebuggerworkitem_offset, false, nullptr, nullptr);

    auto routine = expdebuggerworkitem.Field("WorkerRoutine");
    m_workerroutine_original_offset = routine.m_Offset;
    m_workerroutine_original = routine.GetPtr();

    auto result = WriteVirtualUncached(m_workerroutine_original_offset, &m_code_section_start, g_Ext->m_PtrSize);

    if ( FAILED(result) ) {
        return false;
    }

    return true;
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::HookWorkItemParameter() {
    ExtRemoteTyped expdebuggerworkitem("nt!_WORK_QUEUE_ITEM", m_expdebuggerworkitem_offset, false, nullptr, nullptr);

    auto parameter = expdebuggerworkitem.Field("Parameter");
    m_workerroutine_parameter_original_offset = parameter.m_Offset;
    m_workerroutine_parameter_original = parameter.GetPtr();
    auto result = WriteVirtualUncached(m_workerroutine_parameter_original_offset,
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
    auto result = ReadVirtualUncached(m_workerroutine_parameter_original_offset,
                                      &address,
                                      g_Ext->m_PtrSize);

    if ( SUCCEEDED(result) && address != m_workerroutine_parameter_original ) {
        result = WriteVirtualUncached(m_workerroutine_parameter_original_offset,
                                      &m_workerroutine_parameter_original,
                                      g_Ext->m_PtrSize);
    }
}
//////////////////////////////////////////////////////////////////////////
void WDbgArkRce::UnHookWorkItemRoutine() {
    uint64_t address = 0ULL;
    auto result = ReadVirtualUncached(m_workerroutine_original_offset, &address, g_Ext->m_PtrSize);

    if ( SUCCEEDED(result) && address != m_workerroutine_original ) {
        result = WriteVirtualUncached(m_workerroutine_original_offset, &m_workerroutine_original, g_Ext->m_PtrSize);
    }
}
//////////////////////////////////////////////////////////////////////////
void WDbgArkRce::UnHookWorkItem() {
    UnHookWorkItemParameter();
    UnHookWorkItemRoutine();
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkRce::SetWorkItemState(const WINKD_WORKER_STATE state) {
    auto result = WriteVirtualUncached(m_expdebuggerwork_offset, &state, sizeof(LONG));

    if ( FAILED(result) ) {
        return false;
    }

    return true;
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
