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

#include "analyze.hpp"

#include <string>
#include <algorithm>
#include <utility>
#include <memory>

#include "./ddk.h"

#include "strings.hpp"
#include "symbols.hpp"
#include "util.hpp"
#include "objhelper.hpp"
#include "process.hpp"
#include "processhlp.hpp"

namespace wa {
//////////////////////////////////////////////////////////////////////////
std::string WDbgArkAnalyzeDmlCommand::GetObjectDmlCommand(const ExtRemoteTyped &object) {
    std::string object_type_name("*UNKNOWN*");
    const auto [result_type, type_name] = m_obj_helper->GetObjectTypeName(object);

    if ( FAILED(result_type) ) {
        warn << wa::showqmark << __FUNCTION__ ": GetObjectTypeName failed" << endlwarn;
    } else {
        object_type_name = type_name;
    }

    std::stringstream object_command;

    try {
        const auto [cmd_start_open, cmd_start_close, cmd_end] = m_object_dml_cmd.at(object_type_name);
        object_command << cmd_start_open << std::hex << std::showbase << object.m_Offset;
        object_command << cmd_start_close << std::hex << std::showbase << object.m_Offset << cmd_end;
    } catch ( const std::out_of_range& ) {
        __noop;
    }

    auto result_command = object_command.str();

    if ( result_command.empty() ) {
        object_command << R"(<exec cmd="!object )" << std::hex << std::showbase << object.m_Offset << R"(">)";
        object_command << std::hex << std::showbase << object.m_Offset << "0x39 </exec>";

        result_command = object_command.str();
    }

    return result_command;
}

std::string WDbgArkAnalyzeDmlCommand::GetModuleDmlCommand(const uint64_t address,
                                                          const std::string &module_name,
                                                          const WDbgArkSymbolsBase &symbols_base) {
    std::stringstream module_command_buf;

    module_command_buf << "<link cmd=\"lmDvm " << module_name << "\">" << std::setw(26) << module_name;
    module_command_buf << "<altlink name=\"Dump module (" << module_name << ")\"";

    uint64_t base = 0;
    uint32_t size = 0;

    if ( SUCCEEDED(symbols_base.GetModuleStartSize(address, &base, &size)) ) {
        module_command_buf << "cmd=\".writemem " << m_current_directory;
        module_command_buf << module_name << "_" << std::hex << base << "_" << std::hex << size << ".bin" << " ";
        module_command_buf << std::hex << std::showbase << base << " ";
        module_command_buf << "L?" << std::hex << std::showbase << size;
        module_command_buf << "\" />";
    } else {
        module_command_buf << "cmd=\"*ERROR*\" />";
    }

    module_command_buf << "</link>";

    return module_command_buf.str();
}

std::string WDbgArkAnalyzeDmlCommand::GetTokenDmlCommand(const uint64_t offset) {
    std::stringstream token_ext;

    token_ext << R"(<exec cmd="!token )" << std::hex << std::showbase << offset << R"(">)";
    token_ext << std::internal << std::setw(18) << std::setfill('0');
    token_ext << std::hex << std::showbase << offset << "</exec>";

    return token_ext.str();
}

std::string WDbgArkAnalyzeDmlCommand::GetProcessDmlCommand(const uint64_t offset) {
    std::stringstream proc_ext;

    proc_ext << R"(<exec cmd="dtx nt!_EPROCESS )" << std::hex << std::showbase << offset << R"(">)";
    proc_ext << std::internal << std::setw(18) << std::setfill('0') << std::hex << std::showbase << offset;
    proc_ext << "</exec>";

    return proc_ext.str();
}

std::string WDbgArkAnalyzeDmlCommand::GetProcessDmlInfoCommand(const uint64_t offset, const std::streamsize size) {
    std::stringstream info;

    info << std::setw(size);
    info << "<exec cmd=\"dtx nt!_EPROCESS " << std::hex << std::showbase;
    info << offset << "\">dtx" << "</exec>" << " ";

    info << "<exec cmd=\"!process " << std::hex << std::showbase << offset;
    info << " \">!process" << "</exec>";

    return info.str();
}

std::string WDbgArkAnalyzeDmlCommand::GetAddressDmlCommand(const uint64_t offset) {
    std::stringstream addr_ext;

    if ( offset != 0ULL ) {
        addr_ext << R"(<exec cmd="u )" << std::hex << std::showbase << offset << R"( L10">)";
    }

    addr_ext << std::internal << std::setw(18) << std::setfill('0') << std::hex << std::showbase << offset;

    if ( offset != 0ULL ) {
        addr_ext << "</exec>";
    }

    return addr_ext.str();
}

std::string WDbgArkAnalyzeDmlCommand::GetGdtAddressDmlCommand(const uint64_t offset, const uint32_t selector) {
    std::stringstream addr_ext;

    if ( offset != 0ULL ) {
        if ( g_Ext->IsCurMachine64() ) {
            if ( selector == KGDT64_SYS_TSS ) {
                addr_ext << R"(<exec cmd="dtx nt!_KTSS64 )" << std::hex << std::showbase << offset << R"(">)";
            }
        } else {
            if ( selector == KGDT_TSS || selector == KGDT_DF_TSS || selector == KGDT_NMI_TSS ) {
                addr_ext << R"(<exec cmd="dtx nt!_KTSS )" << std::hex << std::showbase << offset << R"(">)";
            } else if ( selector == KGDT_R0_PCR ) {
                addr_ext << R"(<exec cmd="dtx nt!_KPCR )" << std::hex << std::showbase << offset << R"(">)";
            }
        }
    }

    addr_ext << std::internal << std::setw(18) << std::setfill('0') << std::hex << std::showbase << offset;

    if ( offset != 0ULL ) {
        if ( g_Ext->IsCurMachine64() ) {
            if ( selector == KGDT64_SYS_TSS ) {
                addr_ext << "</exec>";
            }
        } else {
            if ( selector == KGDT_TSS ||
                 selector == KGDT_DF_TSS ||
                 selector == KGDT_NMI_TSS ||
                 selector == KGDT_R0_PCR ) {
                addr_ext << "</exec>";
            }
        }
    }

    return addr_ext.str();
}
//////////////////////////////////////////////////////////////////////////
std::unique_ptr<WDbgArkAnalyzeBase> WDbgArkAnalyzeBase::Create(const std::shared_ptr<WDbgArkSymCache> &sym_cache,
                                                               const AnalyzeType type) {
    switch ( type ) {
        case AnalyzeType::AnalyzeTypeSDT:
        {
            return std::make_unique<WDbgArkAnalyzeSDT>(sym_cache);
        }

        case AnalyzeType::AnalyzeTypeCallback:
        {
            return std::make_unique<WDbgArkAnalyzeCallback>(sym_cache);
        }

        case AnalyzeType::AnalyzeTypeObjType:
        {
            return std::make_unique<WDbgArkAnalyzeObjType>(sym_cache);
        }

        case AnalyzeType::AnalyzeTypeIDT:
        {
            return std::make_unique<WDbgArkAnalyzeIDT>(sym_cache);
        }

        case AnalyzeType::AnalyzeTypeGDT:
        {
            return std::make_unique<WDbgArkAnalyzeGDT>(sym_cache);
        }

        case AnalyzeType::AnalyzeTypeDriver:
        {
            return std::make_unique<WDbgArkAnalyzeDriver>(sym_cache);
        }

        case AnalyzeType::AnalyzeTypeProcessToken:
        {
            return std::make_unique<WDbgArkAnalyzeProcessToken>(sym_cache);
        }

        case AnalyzeType::AnalyzeTypeProcessAnomaly:
        {
            return std::make_unique<WDbgArkAnalyzeProcessAnomaly>(sym_cache);
        }

        case AnalyzeType::AnalyzeTypeDefault:
        default:
        {
            return std::make_unique<WDbgArkAnalyzeDefault>(sym_cache);
        }
    }
}

bool WDbgArkAnalyzeBase::IsSuspiciousAddress(const uint64_t address) const {
    if ( !address ) {
        return false;
    }

    if ( IsAddressInWhiteList(address) ) {
        return false;
    }

    return true;
}

void WDbgArkAnalyzeBase::Analyze(const uint64_t address, const std::string &type, const std::string &info) {
    std::string symbol_name{};
    std::string module_name{};
    std::string image_name{};
    std::string loaded_image_name{};
    std::string module_command{};

    auto suspicious = IsSuspiciousAddress(address);

    if ( address ) {
        symbol_name = "*UNKNOWN*";
        module_name = "*UNKNOWN*";

        WDbgArkSymbolsBase symbols_base;

        if ( FAILED(symbols_base.GetModuleNames(address, &image_name, &module_name, &loaded_image_name)) ) {
            suspicious = true;
        }

        module_command = GetModuleDmlCommand(address, module_name, symbols_base);

        const auto [result, name] = symbols_base.GetNameByOffset(address);

        if ( FAILED(result) ) {
            suspicious = true;
        } else {
            symbol_name = name;
        }
    }

    const auto address_command = GetAddressDmlCommand(address);

    *m_tp << address_command << type << symbol_name << module_command;

    if ( suspicious ) {
        *m_tp << "Y";
    } else {
        *m_tp << "";
    }

    if ( !info.empty() ) {
        *m_tp << info;
    }

    if ( suspicious ) {
        m_tp->flush_warn();
    } else {
        m_tp->flush_out();
    }
}
//////////////////////////////////////////////////////////////////////////
void WDbgArkAnalyzeBase::PrintObjectDmlCmd(const ExtRemoteTyped &object) {
    const auto [result, object_name] = m_obj_helper->GetObjectName(object);

    if ( FAILED(result) ) {
        warn << wa::showqmark << __FUNCTION__ ": GetObjectName failed" << endlwarn;
    }

    const auto object_command = GetObjectDmlCommand(object);

    *this << object_command << object_name;
    m_tp->flush_out();
}
//////////////////////////////////////////////////////////////////////////
WDbgArkAnalyzeDefault::WDbgArkAnalyzeDefault(const std::shared_ptr<WDbgArkSymCache> &sym_cache)
    : WDbgArkAnalyzeBase(sym_cache) {
    // width = 190
    AddColumn("Address", 18);
    AddColumn("Name", 68);
    AddColumn("Symbol", 68);
    AddColumn("Module", 26);
    AddColumn("Suspicious", 10);
}
//////////////////////////////////////////////////////////////////////////
WDbgArkAnalyzeSDT::WDbgArkAnalyzeSDT(const std::shared_ptr<WDbgArkSymCache> &sym_cache)
    : WDbgArkAnalyzeBase(sym_cache) {
    // width = 195
    AddColumn("#", 5);
    AddColumn("Address", 18);
    AddColumn("Name", 68);
    AddColumn("Symbol", 68);
    AddColumn("Module", 26);
    AddColumn("Suspicious", 10);
}
void WDbgArkAnalyzeSDT::Analyze(const uint64_t address, const std::string &type) {
    WDbgArkAnalyzeBase* display = this;

    std::stringstream str_index;
    str_index << std::hex << index++;

    *this << str_index.str();
    display->Analyze(address, type, "");
}
//////////////////////////////////////////////////////////////////////////
WDbgArkAnalyzeCallback::WDbgArkAnalyzeCallback(const std::shared_ptr<WDbgArkSymCache> &sym_cache)
    : WDbgArkAnalyzeBase(sym_cache) {
    // width = 190
    AddColumn("Address", 18);
    AddColumn("Type", 25);
    AddColumn("Symbol", 86);
    AddColumn("Module", 26);
    AddColumn("Suspicious", 10);
    AddColumn("Info", 25);
}
//////////////////////////////////////////////////////////////////////////
WDbgArkAnalyzeObjType::WDbgArkAnalyzeObjType(const std::shared_ptr<WDbgArkSymCache> &sym_cache)
    : WDbgArkAnalyzeBase(sym_cache) {
    // width = 200
    AddColumn("Address", 18);
    AddColumn("Name", 68);
    AddColumn("Symbol", 78);
    AddColumn("Module", 26);
    AddColumn("Suspicious", 10);
}

void WDbgArkAnalyzeObjType::Analyze(const ExtRemoteTyped &ex_type_info, const ExtRemoteTyped &object) {
    ExtRemoteTyped obj_type_info = ex_type_info;

    try {
        PrintObjectDmlCmd(object);
        PrintFooter();

        const auto [result, name] = m_obj_helper->GetObjectName(object);

        if ( SUCCEEDED(result) ) {
            AddTempWhiteList(name);
        }

        WDbgArkAnalyzeBase* display = this;

        std::string parse_procedure_name("ParseProcedure");

        if ( obj_type_info.HasField("UseExtendedParameters") &&
             obj_type_info.Field("UseExtendedParameters").GetUchar() & 1 ) {
            parse_procedure_name = "ParseProcedureEx";
        }

        display->Analyze(obj_type_info.Field("DumpProcedure").GetPtr(), "DumpProcedure", "");
        display->Analyze(obj_type_info.Field("OpenProcedure").GetPtr(), "OpenProcedure", "");
        display->Analyze(obj_type_info.Field("CloseProcedure").GetPtr(), "CloseProcedure", "");
        display->Analyze(obj_type_info.Field("DeleteProcedure").GetPtr(), "DeleteProcedure", "");
        display->Analyze(obj_type_info.Field(parse_procedure_name.c_str()).GetPtr(), parse_procedure_name.c_str(), "");
        display->Analyze(obj_type_info.Field("SecurityProcedure").GetPtr(), "SecurityProcedure", "");
        display->Analyze(obj_type_info.Field("SecurityProcedure").GetPtr(), "QueryNameProcedure", "");
        PrintFooter();
    }
    catch(const ExtRemoteException &Ex) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    InvalidateTempRanges();
}
//////////////////////////////////////////////////////////////////////////
WDbgArkAnalyzeIDT::WDbgArkAnalyzeIDT(const std::shared_ptr<WDbgArkSymCache> &sym_cache)
    : WDbgArkAnalyzeBase(sym_cache) {
    // width = 170
    AddColumn("Address", 18);
    AddColumn("CPU / Idx", 11);
    AddColumn("Symbol", 80);
    AddColumn("Module", 26);
    AddColumn("Suspicious", 10);
    AddColumn("Info", 25);
}
//////////////////////////////////////////////////////////////////////////
WDbgArkAnalyzeGDT::WDbgArkAnalyzeGDT(const std::shared_ptr<WDbgArkSymCache> &sym_cache)
    : WDbgArkAnalyzeBase(sym_cache) {
    // width = 133
    AddColumn("Base", 18);
    AddColumn("Limit", 10);
    AddColumn("CPU / Idx", 10);
    AddColumn("Offset", 10);
    AddColumn("Selector name", 20);
    AddColumn("Type", 20);
    AddColumn("DPL", 4);
    AddColumn("Gr", 4);     // Granularity
    AddColumn("Pr", 4);     // Present
    AddColumn("Info", 25);
}

void WDbgArkAnalyzeGDT::Analyze(const ExtRemoteTyped &gdt_entry,
                                const std::string &cpu_idx,
                                const uint32_t selector,
                                const std::string &additional_info) {
    try {
        const uint32_t limit = GetGDTLimit(gdt_entry);
        uint64_t address = 0ULL;

        if ( !NormalizeAddress(GetGDTBase(gdt_entry), &address) ) {
            err << wa::showminus << __FUNCTION__ << ": NormalizeAddress failed" << endlerr;
        }

        const auto address_command = GetGdtAddressDmlCommand(address, selector);

        std::stringstream selector_ext;
        selector_ext << std::hex << std::showbase << selector;

        std::stringstream limit_ext;
        limit_ext << std::internal << std::setw(10) << std::setfill('0') << std::hex << std::showbase << limit;

        std::stringstream dpl;
        dpl << std::dec << GetGDTDpl(gdt_entry);

        std::stringstream granularity;

        if ( IsGDTPageGranularity(gdt_entry) ) {
            granularity << "Page";
        } else {
            granularity << "Byte";
        }

        std::stringstream present;

        if ( IsGDTFlagPresent(gdt_entry) ) {
            present << "P";
        } else {
            present << "NP";
        }

        *this << address_command << limit_ext.str() << cpu_idx << selector_ext.str();
        *this << GetGDTSelectorName(selector) << GetGDTTypeName(gdt_entry);
        *this << dpl.str() << granularity.str() << present.str() << additional_info;

        FlushOut();
    }
    catch( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
}

bool WDbgArkAnalyzeGDT::IsGDTPageGranularity(const ExtRemoteTyped &gdt_entry) {
    ExtRemoteTyped loc_gdt_entry = gdt_entry;
    std::string field_name;

    if ( g_Ext->IsCurMachine64() ) {
        field_name = "Bits.Granularity";
    } else {
        field_name = "HighWord.Bits.Granularity";
    }

    return (loc_gdt_entry.Field(field_name.c_str()).GetUlong() == 1);
}

bool WDbgArkAnalyzeGDT::IsGDTFlagPresent(const ExtRemoteTyped &gdt_entry) {
    ExtRemoteTyped loc_gdt_entry = gdt_entry;
    std::string field_name;

    if ( g_Ext->IsCurMachine64() ) {
        field_name = "Bits.Present";
    } else {
        field_name = "HighWord.Bits.Pres";
    }

    return (loc_gdt_entry.Field(field_name.c_str()).GetUlong() == 1);
}

uint32_t WDbgArkAnalyzeGDT::GetGDTDpl(const ExtRemoteTyped &gdt_entry) {
    ExtRemoteTyped loc_gdt_entry = gdt_entry;
    std::string field_name;

    if ( g_Ext->IsCurMachine64() ) {
        field_name = "Bits.Dpl";
    } else {
        field_name = "HighWord.Bits.Dpl";
    }

    return loc_gdt_entry.Field(field_name.c_str()).GetUlong();
}

uint32_t WDbgArkAnalyzeGDT::GetGDTType(const ExtRemoteTyped &gdt_entry) {
    ExtRemoteTyped loc_gdt_entry = gdt_entry;
    std::string field_name;

    if ( g_Ext->IsCurMachine64() ) {
        field_name = "Bits.Type";
    } else {
        field_name = "HighWord.Bits.Type";
    }

    return loc_gdt_entry.Field(field_name.c_str()).GetUlong();
}

bool WDbgArkAnalyzeGDT::IsGDTTypeSystem(const ExtRemoteTyped &gdt_entry) {
    return (GetGDTType(gdt_entry) & SEG_DESCTYPE(1)) == 0;
}

uint32_t WDbgArkAnalyzeGDT::GetGDTLimit(const ExtRemoteTyped &gdt_entry) {
    ExtRemoteTyped loc_gdt_entry = gdt_entry;
    uint32_t limit = 0;

    if ( g_Ext->IsCurMachine64() ) {
        limit = (loc_gdt_entry.Field("Bits.LimitHigh").GetUlong() << 16) |\
                (loc_gdt_entry.Field("LimitLow").GetUshort());
    } else {
        limit = (loc_gdt_entry.Field("HighWord.Bits.LimitHi").GetUlong() << 16) |\
                (loc_gdt_entry.Field("LimitLow").GetUshort());
    }

    if ( IsGDTPageGranularity(gdt_entry) ) {    // 4k segment
        limit = ((limit + 1) << PAGE_SHIFT) - 1;
    }

    return limit;
}

uint64_t WDbgArkAnalyzeGDT::GetGDTBase(const ExtRemoteTyped &gdt_entry) {
    ExtRemoteTyped loc_gdt_entry = gdt_entry;
    uint64_t base = 0;

    if ( g_Ext->IsCurMachine64() ) {
        base =\
            (static_cast<uint64_t>(loc_gdt_entry.Field("BaseLow").GetUshort())) |\
            (static_cast<uint64_t>(loc_gdt_entry.Field("Bytes.BaseMiddle").GetUchar()) << 16) |\
            (static_cast<uint64_t>(loc_gdt_entry.Field("Bytes.BaseHigh").GetUchar()) << 24) |\
            (static_cast<uint64_t>(loc_gdt_entry.Field("BaseUpper").GetUlong()) << 32);
    } else {
        base =\
            (static_cast<uint64_t>(loc_gdt_entry.Field("BaseLow").GetUshort())) |\
            (static_cast<uint64_t>(loc_gdt_entry.Field("HighWord.Bytes.BaseMid").GetUchar()) << 16) |\
            (static_cast<uint64_t>(loc_gdt_entry.Field("HighWord.Bytes.BaseHi").GetUchar()) << 24);
    }

    return base;
}

std::string WDbgArkAnalyzeGDT::GetGDTSelectorName(const uint32_t selector) const {
    std::string selector_name = "*RESERVED*";

    try {
        if ( g_Ext->IsCurMachine64() ) {
            selector_name = m_gdt_selector_x64.at(selector);
        } else {
            selector_name = m_gdt_selector_x86.at(selector);
        }
    } catch ( const std::out_of_range& ) {
        __noop;
    }

    return selector_name;
}

std::string WDbgArkAnalyzeGDT::GetGDTTypeName(const ExtRemoteTyped &gdt_entry) {
    std::string type_name = "*UNKNOWN*";
    const size_t type = static_cast<size_t>(GetGDTType(gdt_entry) & ~SEG_DESCTYPE(1));

    try {
        if ( IsGDTTypeSystem(gdt_entry) ) {
            if ( g_Ext->IsCurMachine64() ) {
                type_name = m_gdt_sys_x64.at(type);     // system, x64
            } else {
                type_name = m_gdt_sys_x86.at(type);     // system, x86
            }
        } else {
            type_name = m_gdt_code_data.at(type);       // code/data x86/x64
        }
    } catch ( const std::out_of_range& ) {
        __noop;
    }

    return type_name;
}
//////////////////////////////////////////////////////////////////////////
WDbgArkAnalyzeDriver::WDbgArkAnalyzeDriver(const std::shared_ptr<WDbgArkSymCache> &sym_cache)
    : WDbgArkAnalyzeBase(sym_cache) {
    // width = 190
    AddColumn("Address", 18);
    AddColumn("Name", 68);
    AddColumn("Symbol", 68);
    AddColumn("Module", 26);
    AddColumn("Suspicious", 10);
}

void WDbgArkAnalyzeDriver::Analyze(const ExtRemoteTyped &object) {
    auto loc_object = const_cast<ExtRemoteTyped&>(object);

    try {
        PrintObjectDmlCmd(object);
        PrintFooter();

        WDbgArkAnalyzeBase* display = this;

        auto driver_start = loc_object.Field("DriverStart").GetPtr();
        uint32_t driver_size = loc_object.Field("DriverSize").GetUlong();

        if ( driver_start && driver_size ) {
            display->AddTempRangeWhiteList(driver_start, driver_size);
        }

        const auto [result, name] = m_obj_helper->GetObjectName(object);

        if ( SUCCEEDED(result) ) {
            AddTempWhiteList(name);
        }

        auto driver_extension = loc_object.Field("DriverExtension");

        if ( driver_extension.GetPtr() ) {
            auto key_name = driver_extension.Field("ServiceKeyName");
            const auto [result_service, sevice_name] = UnicodeStringStructToString(key_name);

            if ( SUCCEEDED(result_service) ) {
                wout << wa::showplus<wchar_t> << L"ServiceKeyName: " << sevice_name << endlout<wchar_t>;
            }
        }

        out << wa::showplus << "Driver routines: " << endlout;
        PrintFooter();

        display->Analyze(loc_object.Field("DriverInit").GetPtr(), "DriverInit", "");
        display->Analyze(loc_object.Field("DriverStartIo").GetPtr(), "DriverStartIo", "");
        display->Analyze(loc_object.Field("DriverUnload").GetPtr(), "DriverUnload", "");

        if ( driver_extension.GetPtr() ) {
            display->Analyze(driver_extension.Field("AddDevice").GetPtr(), "AddDevice", "");
        }

        PrintFooter();

        // display major table
        DisplayMajorTable(object);

        // display fast i/o table
        DisplayFastIo(object);

        // display FsFilterCallbacks
        DisplayFsFilterCallbacks(object);

        // display classpnp routines
        DisplayClassCallbacks(object);
    } catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    } catch ( const ExtException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    PrintFooter();
    InvalidateTempRanges();
}

void WDbgArkAnalyzeDriver::DisplayMajorTable(const ExtRemoteTyped &object) {
    WDbgArkAnalyzeBase* display = this;

    out << wa::showplus << "Major table routines: " << endlout;
    PrintFooter();

    const auto major_table = WDbgArkDrvObjHelper(m_sym_cache, object).GetMajorTable();

    for ( const auto [address, type] : major_table ) {
        display->Analyze(address, type, "");
    }

    PrintFooter();
}

void WDbgArkAnalyzeDriver::DisplayFastIo(const ExtRemoteTyped &object) {
    WDbgArkAnalyzeBase* display = this;

    const auto fast_io_table = WDbgArkDrvObjHelper(m_sym_cache, object).GetFastIoTable();

    if ( !fast_io_table.empty() ) {
        out << wa::showplus << "FastIO table routines: " << endlout;
        PrintFooter();

        for ( const auto [address, type] : fast_io_table ) {
            display->Analyze(address, type, "");
        }

        PrintFooter();
    }
}

void WDbgArkAnalyzeDriver::DisplayFsFilterCallbacks(const ExtRemoteTyped &object) {
    WDbgArkAnalyzeBase* display = this;

    const auto fs_cb_table = WDbgArkDrvObjHelper(m_sym_cache, object).GetFsFilterCbTable();

    if ( !fs_cb_table.empty() ) {
        out << wa::showplus << "FsFilterCallbacks table routines: " << endlout;
        PrintFooter();

        for ( const auto [address, type] : fs_cb_table ) {
            display->Analyze(address, type, "");
        }

        PrintFooter();
    }
}

/*
driverExtension = IoGetDriverObjectExtension(DriverObject, CLASS_DRIVER_EXTENSION_KEY);
#define CLASS_DRIVER_EXTENSION_KEY ((PVOID) ClassInitialize)

NTKERNELAPI
PVOID
IoGetDriverObjectExtension(
    IN PDRIVER_OBJECT DriverObject,
    IN PVOID ClientIdentificationAddress
    )

Routine Description:

    This routine returns a pointer to the client driver object extension.
    This extension was allocated using IoAllocateDriverObjectExtension. If
    an extension with the create Id does not exist for the specified driver
    object then NULL is returned.

Arguments:

    DriverObject - Pointer to driver object owning the extension.

    ClientIdentificationAddress - Supplies the unique identifier which was
        used to create the extension.

Return Value:

    The function value is a pointer to the client driver object extension,
    or NULL.
--

{
    KIRQL irql;
    PIO_CLIENT_EXTENSION extension;

    irql = KeAcquireQueuedSpinLock( LockQueueIoDatabaseLock );
    extension = DriverObject->DriverExtension->ClientDriverExtension;
    while (extension != NULL) {

        if (extension->ClientIdentificationAddress == ClientIdentificationAddress) {
            break;
        }

        extension = extension->NextExtension;
    }

    KeReleaseQueuedSpinLock( LockQueueIoDatabaseLock, irql );

    if (extension == NULL) {
        return NULL;
    }

    return extension + 1;
}
*/

void WDbgArkAnalyzeDriver::DisplayClassCallbacks(const ExtRemoteTyped &object) {
    WDbgArkAnalyzeBase* display = this;

    WDbgArkClassDrvObjHelper class_ext(m_sym_cache, object);

    if ( !class_ext.HasClassDriverExtension() ) {
        return;
    }

    *this << class_ext.GetClassExtensionDmlCommand();   // display DML command for Class Driver Extension
    FlushOut();
    PrintFooter();

    AddTempWhiteList("classpnp");

    out << wa::showplus << "Class Driver extension routines: " << endlout;
    PrintFooter();

    display->Analyze(class_ext.Field("ClassFdoQueryWmiRegInfoEx").GetPtr(), "ClassFdoQueryWmiRegInfoEx", "");
    display->Analyze(class_ext.Field("ClassPdoQueryWmiRegInfoEx").GetPtr(), "ClassPdoQueryWmiRegInfoEx", "");
    PrintFooter();

    const auto init_data = class_ext.GetInitDataTable();

    if ( !init_data.empty() ) {
        out << wa::showplus << "Class Driver extension InitData routines: " << endlout;
        PrintFooter();

        for ( const auto [address, type] : init_data ) {
            display->Analyze(address, type, "");
        }

        PrintFooter();
    }

    // FDO
    const auto init_data_fdo = class_ext.GetInitDataFdoDataTable();

    if ( !init_data_fdo.empty() ) {
        out << wa::showplus << "Class Driver extension InitData.FdoData routines: " << endlout;
        PrintFooter();

        for ( const auto [address, type] : init_data_fdo ) {
            display->Analyze(address, type, "");
        }

        PrintFooter();
    }

    const auto init_data_fdo_wmi = class_ext.GetInitDataFdoDataWmiTable();

    if ( !init_data_fdo_wmi.empty() ) {
        out << wa::showplus << "Class Driver extension InitData.FdoData.ClassWmiInfo routines: " << endlout;
        PrintFooter();

        for ( const auto [address, type] : init_data_fdo_wmi ) {
            display->Analyze(address, type, "");
        }

        PrintFooter();
    }

    // PDO
    const auto init_data_pdo = class_ext.GetInitDataPdoDataTable();

    if ( !init_data_pdo.empty() ) {
        out << wa::showplus << "Class Driver extension InitData.PdoData routines: " << endlout;
        PrintFooter();

        for ( const auto [address, type] : init_data_pdo ) {
            display->Analyze(address, type, "");
        }

        PrintFooter();
    }

    const auto init_data_pdo_wmi = class_ext.GetInitDataPdoDataWmiTable();

    if ( !init_data_pdo_wmi.empty() ) {
        out << wa::showplus << "Class Driver extension InitData.PdoData.ClassWmiInfo routines: " << endlout;
        PrintFooter();

        for ( const auto [address, type] : init_data_pdo_wmi ) {
            display->Analyze(address, type, "");
        }

        PrintFooter();
    }

    // DeviceMajorFunctionTable
    const auto dev_major_table = class_ext.GetDeviceMajorFunctionTable();

    if ( !dev_major_table.empty() ) {
        out << wa::showplus << "Class Driver extension InitData.DeviceMajorFunctionTable routines: " << endlout;
        PrintFooter();

        for ( const auto [address, type] : dev_major_table ) {
            display->Analyze(address, type, "");
        }

        PrintFooter();
    }

    // MpDeviceMajorFunctionTable
    const auto mp_dev_major_table = class_ext.GetMpDeviceMajorFunctionTable();

    if ( !mp_dev_major_table.empty() ) {
        out << wa::showplus << "Class Driver extension InitData.MpDeviceMajorFunctionTable routines: " << endlout;
        PrintFooter();

        for ( const auto [address, type] : mp_dev_major_table ) {
            display->Analyze(address, type, "");
        }

        PrintFooter();
    }
}
//////////////////////////////////////////////////////////////////////////
WDbgArkAnalyzeProcessToken::WDbgArkAnalyzeProcessToken(const std::shared_ptr<WDbgArkSymCache> &sym_cache)
    : WDbgArkAnalyzeBase(sym_cache) {
    // width = 216
    AddColumn("Token", 18);
    AddColumn("Process name", 25);
    AddColumn("Process image path", 113);
    AddColumn("Suspicious", 10);
    AddColumn("Anomaly type", 25);
    AddColumn("Info", 25);

    if ( m_sym_cache->GetTypeSize("nt!_SEP_TOKEN_PRIVILEGES") != 0UL ) {
        m_check_token_privileges = true;
    }
}

void WDbgArkAnalyzeProcessToken::Analyze(const WDbgArkRemoteTypedProcess &process) {
    CheckTokenStolen(process);

    if ( m_check_token_privileges == true ) {
        CheckTokenPrivileges(process);
    }
}

bool WDbgArkAnalyzeProcessToken::IsPrinted(const WDbgArkRemoteTypedProcess &process) {
    const auto [it, inserted] = m_printed.insert(process.GetDataOffset());
    return !(inserted);
}

void WDbgArkAnalyzeProcessToken::CheckTokenStolen(const WDbgArkRemoteTypedProcess &process) {
    auto check_process = const_cast<WDbgArkRemoteTypedProcess&>(process);

    try {
        const auto token_ref = check_process.Field("Token.Object").GetPtr();

        if ( token_ref != 0ULL ) {
            const auto token = ExFastRefGetObject(token_ref);
            const auto [it, inserted] = m_token_process.try_emplace(token, check_process);

            if ( !inserted ) {
                auto [key_token, known_process] = *it;

                const auto token_cmd = GetTokenDmlCommand(token);

                if ( !IsPrinted(known_process) ) {
                    // output first process
                    std::string known_image_name{};
                    std::wstring known_image_path{};

                    try {
                        known_process.GetProcessImageFileName(&known_image_name);
                        known_process.GetProcessImageFilePath(&known_image_path);
                    } catch ( const ExtRemoteException &Ex ) {
                        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
                    }

                    const auto known_info_cmd = GetProcessDmlInfoCommand(known_process.GetDataOffset(), 41);

                    *this << token_cmd << known_image_name << wstring_to_string(known_image_path);
                    *this << "Y" << m_anomaly_type_token_stolen << known_info_cmd;

                    FlushWarn();
                    PrintFooter();
                }

                if ( !IsPrinted(check_process) ) {
                    // output second process
                    std::string check_image_name{};
                    std::wstring check_image_path{};

                    try {
                        check_process.GetProcessImageFileName(&check_image_name);
                        check_process.GetProcessImageFilePath(&check_image_path);
                    } catch ( const ExtRemoteException &Ex ) {
                        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
                    }

                    const auto check_info_cmd = GetProcessDmlInfoCommand(check_process.GetDataOffset(), 41);

                    *this << token_cmd << check_image_name << wstring_to_string(check_image_path);
                    *this << "Y" << m_anomaly_type_token_stolen << check_info_cmd;

                    FlushWarn();
                    PrintFooter();
                }
            }
        }
    } catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
}

void WDbgArkAnalyzeProcessToken::CheckTokenPrivileges(const WDbgArkRemoteTypedProcess &process) {
    auto check_process = const_cast<WDbgArkRemoteTypedProcess&>(process);

    try {
        const auto token_ref = check_process.Field("Token.Object").GetPtr();

        if ( token_ref != 0ULL ) {
            const auto token = ExFastRefGetObject(token_ref);

            const std::string token_str("nt!_TOKEN");
            auto privileges = ExtRemoteTyped(token_str.c_str(),
                                             token,
                                             false,
                                             m_sym_cache->GetCookieCache(token_str),
                                             nullptr).Field("Privileges");

            const auto present = privileges.Field("Present").GetUlong64();
            const auto enabled = privileges.Field("Enabled").GetUlong64();
            const auto enabled_by_default = privileges.Field("EnabledByDefault").GetUlong64();

            if ( present == UINT64_MAX || enabled == UINT64_MAX || enabled_by_default == UINT64_MAX ) {
                const auto token_cmd = GetTokenDmlCommand(token);

                std::string image_name{};
                std::wstring image_path{};

                try {
                    check_process.GetProcessImageFileName(&image_name);
                    check_process.GetProcessImageFilePath(&image_path);
                } catch ( const ExtRemoteException &Ex ) {
                    err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
                }

                const auto info_cmd = GetProcessDmlInfoCommand(check_process.GetDataOffset(), 41);

                *this << token_cmd << image_name << wstring_to_string(image_path) << "Y" << m_anomaly_type_token_privs;
                *this << info_cmd;

                FlushWarn();
                PrintFooter();
            }
        }
    } catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
}
//////////////////////////////////////////////////////////////////////////
WDbgArkAnalyzeProcessAnomaly::WDbgArkAnalyzeProcessAnomaly(const std::shared_ptr<WDbgArkSymCache> &sym_cache)
    : WDbgArkAnalyzeBase(sym_cache) {
    // width = 216
    AddColumn("Process", 18);
    AddColumn("Process name", 25);
    AddColumn("Process image path", 113);
    AddColumn("Suspicious", 10);
    AddColumn("Anomaly type", 25);
    AddColumn("Info", 25);
}

void WDbgArkAnalyzeProcessAnomaly::Analyze(const WDbgArkRemoteTypedProcess &process) {
    auto check_process = const_cast<WDbgArkRemoteTypedProcess&>(process);

    try {
        std::string type{};

        if ( IsSuspiciousProcess(process, &type) ) {
            std::string image_name{};
            std::wstring image_path{};

            check_process.GetProcessImageFileName(&image_name);
            check_process.GetProcessImageFilePath(&image_path);

            const auto process_command = GetProcessDmlCommand(check_process.GetDataOffset());

            *this << process_command << image_name << wstring_to_string(image_path) << "Y" << type << "";

            FlushWarn();
            PrintFooter();
        }
    } catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
}

bool WDbgArkAnalyzeProcessAnomaly::IsSuspiciousProcess(const WDbgArkRemoteTypedProcess &process, std::string* type) {
    if ( CheckProcessDoppelgang(process) ) {
        *type = m_anomaly_type_process_doppel;
        return true;
    }

    return false;
}

bool WDbgArkAnalyzeProcessAnomaly::CheckProcessDoppelgang(const WDbgArkRemoteTypedProcess &process) {
    auto check_process = const_cast<WDbgArkRemoteTypedProcess&>(process);

    try {
        // skip System process
        if ( check_process.IsSystemProcess() ) {
            return false;
        }

        // skip Minimal process
        if ( check_process.IsMinimalProcess() ) {
            return false;
        }

        // we need to check FILE_OBJECT for the WriteAccess flag
        ExtRemoteTyped file_object;

        // this is suspicious, but we are looking just for Doppelganged process
        if ( !check_process.GetProcessFileObject(&file_object) ) {
            return false;
        }

        const auto write_access = file_object.Field("WriteAccess").GetUchar();

        // if process has ImageFilePointer then check the pointer also
        if ( check_process.HasField("ImageFilePointer") ) {
            if ( !check_process.Field("ImageFilePointer").GetPtr() && write_access == 1 ) {
                return true;
            }
        } else {
            if ( write_access == 1 ) {
                return true;
            }
        }
    } catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    return false;
}

}   // namespace wa
