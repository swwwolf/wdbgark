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

#include "analyze.hpp"

#include <string>
#include <algorithm>
#include <utility>
#include <memory>

#include "./ddk.h"

#include "strings.hpp"
#include "symbols.hpp"
#include "util.hpp"

namespace wa {
//////////////////////////////////////////////////////////////////////////
std::unique_ptr<WDbgArkAnalyzeBase> WDbgArkAnalyzeBase::Create(const std::shared_ptr<WDbgArkSymCache> &sym_cache,
                                                               const AnalyzeType type) {
    switch ( type ) {
        case AnalyzeType::AnalyzeTypeSDT:
            return std::make_unique<WDbgArkAnalyzeSDT>(sym_cache);
        break;

        case AnalyzeType::AnalyzeTypeCallback:
            return std::make_unique<WDbgArkAnalyzeCallback>(sym_cache);
        break;

        case AnalyzeType::AnalyzeTypeObjType:
            return std::make_unique<WDbgArkAnalyzeObjType>(sym_cache);
        break;

        case AnalyzeType::AnalyzeTypeIDT:
            return std::make_unique<WDbgArkAnalyzeIDT>(sym_cache);
        break;

        case AnalyzeType::AnalyzeTypeGDT:
            return std::make_unique<WDbgArkAnalyzeGDT>(sym_cache);
        break;

        case AnalyzeType::AnalyzeTypeDriver:
            return std::make_unique<WDbgArkAnalyzeDriver>(sym_cache);
        break;

        case AnalyzeType::AnalyzeTypeDefault:
        default:
            return std::make_unique<WDbgArkAnalyzeDefault>(sym_cache);
        break;
    }
}

bool WDbgArkAnalyzeBase::IsSuspiciousAddress(const uint64_t address) const {
    if ( !address )
        return false;

    if ( IsAddressInWhiteList(address) )
        return false;

    return true;
}

void WDbgArkAnalyzeBase::Analyze(const uint64_t address,
                                 const std::string &type,
                                 const std::string &additional_info) {
    std::string symbol_name;
    std::string module_name;
    std::string image_name;
    std::string loaded_image_name;
    std::stringstream module_command_buf;

    bool suspicious = IsSuspiciousAddress(address);

    if ( address ) {
        symbol_name = "*UNKNOWN*";
        module_name = "*UNKNOWN*";

        WDbgArkSymbolsBase symbols_base;
        if ( !SUCCEEDED(symbols_base.GetModuleNames(address, &image_name, &module_name, &loaded_image_name)) )
            suspicious = true;

        module_command_buf << "<link cmd=\"lmDvm " << module_name << "\">" << std::setw(16) << module_name;
        module_command_buf << "<altlink name=\"Dump module (" << module_name << ")\"";

        uint64_t base = 0;
        uint32_t size = 0;

        if ( SUCCEEDED(symbols_base.GetModuleStartSize(address, &base, &size)) ) {
            module_command_buf << "cmd=\".writemem ";

            char current_dir[MAX_PATH];
            if ( GetCurrentDirectory(MAX_PATH, current_dir) && GetShortPathName(current_dir, current_dir, MAX_PATH) )
                module_command_buf << current_dir << "\\";

            module_command_buf << module_name << "_" << std::hex << base << "_" << std::hex << size << ".bin" << " ";
            module_command_buf << std::hex << std::showbase << base << " ";
            module_command_buf << "L?" << std::hex << std::showbase << size;
            module_command_buf << "\" />";
        } else {
            module_command_buf << "cmd=\"*ERROR*\" />";
        }

        module_command_buf << "</link>";

        std::pair<HRESULT, std::string> result = symbols_base.GetNameByOffset(address);

        if ( !SUCCEEDED(result.first) )
            suspicious = true;
        else
            symbol_name = result.second;
    }

    std::stringstream addr_ext;

    if ( address )
        addr_ext << "<exec cmd=\"u " << std::hex << std::showbase << address << " L10\">";

    addr_ext << std::internal << std::setw(18) << std::setfill('0') << std::hex << std::showbase << address;

    if ( address )
        addr_ext << "</exec>";

    *m_tp << addr_ext.str() << type << symbol_name << module_command_buf.str();

    if ( suspicious )
        *m_tp << "Y";
    else
        *m_tp << "";

    if ( !additional_info.empty() )
        *m_tp << additional_info;

    if ( suspicious )
        m_tp->flush_warn();
    else
        m_tp->flush_out();
}
//////////////////////////////////////////////////////////////////////////
void WDbgArkAnalyzeBase::PrintObjectDmlCmd(const ExtRemoteTyped &object) {
    std::string object_name = "*UNKNOWN*";

    auto result = m_obj_helper->GetObjectName(object);

    if ( !SUCCEEDED(result.first) ) {
        std::stringstream warn;
        warn << wa::showqmark << __FUNCTION__ ": GetObjectName failed" << endlwarn;
    } else {
        object_name = result.second;
    }

    std::string object_type_name = "*UNKNOWN*";
    result = m_obj_helper->GetObjectTypeName(object);

    if ( !SUCCEEDED(result.first) ) {
        std::stringstream warn;
        warn << wa::showqmark << __FUNCTION__ ": GetObjectTypeName failed" << endlwarn;
    } else {
        object_type_name = result.second;
    }

    std::stringstream object_command;
    std::stringstream object_name_ext;

    try {
        auto obj_dml_cmd = m_object_dml_cmd.at(object_type_name);
        object_command << std::get<0>(obj_dml_cmd) << std::hex << std::showbase << object.m_Offset;
        object_command << std::get<1>(obj_dml_cmd);
        object_command << std::hex << std::showbase << object.m_Offset << std::get<2>(obj_dml_cmd);
    } catch ( const std::out_of_range& ) {}

    if ( object_command.str().empty() ) {
        object_command << "<exec cmd=\"!object " << std::hex << std::showbase << object.m_Offset << "\">";
        object_command << std::hex << std::showbase << object.m_Offset << "</exec>";
    }

    object_name_ext << object_name;

    *this << object_command.str() << object_name_ext.str();
    m_tp->flush_out();
}
//////////////////////////////////////////////////////////////////////////
WDbgArkAnalyzeDefault::WDbgArkAnalyzeDefault(const std::shared_ptr<WDbgArkSymCache> &sym_cache)
    : WDbgArkAnalyzeBase(sym_cache) {
    // width = 180
    AddColumn("Address", 18);
    AddColumn("Name", 68);
    AddColumn("Symbol", 68);
    AddColumn("Module", 16);
    AddColumn("Suspicious", 10);
}
//////////////////////////////////////////////////////////////////////////
WDbgArkAnalyzeSDT::WDbgArkAnalyzeSDT(const std::shared_ptr<WDbgArkSymCache> &sym_cache)
    : WDbgArkAnalyzeBase(sym_cache) {
    // width = 185
    AddColumn("#", 5);
    AddColumn("Address", 18);
    AddColumn("Name", 68);
    AddColumn("Symbol", 68);
    AddColumn("Module", 16);
    AddColumn("Suspicious", 10);
}
void WDbgArkAnalyzeSDT::Analyze(const uint64_t address, const std::string &type) {
    WDbgArkAnalyzeBase* display = static_cast<WDbgArkAnalyzeBase*>(this);

    std::stringstream str_index;
    str_index << std::hex << index++;
    *this << str_index.str();
    display->Analyze(address, type, "");
}
//////////////////////////////////////////////////////////////////////////
WDbgArkAnalyzeCallback::WDbgArkAnalyzeCallback(const std::shared_ptr<WDbgArkSymCache> &sym_cache)
    : WDbgArkAnalyzeBase(sym_cache) {
    // width = 180
    AddColumn("Address", 18);
    AddColumn("Type", 25);
    AddColumn("Symbol", 86);
    AddColumn("Module", 16);
    AddColumn("Suspicious", 10);
    AddColumn("Info", 25);
}
//////////////////////////////////////////////////////////////////////////
WDbgArkAnalyzeObjType::WDbgArkAnalyzeObjType(const std::shared_ptr<WDbgArkSymCache> &sym_cache)
    : WDbgArkAnalyzeBase(sym_cache) {
    // width = 180
    AddColumn("Address", 18);
    AddColumn("Name", 68);
    AddColumn("Symbol", 68);
    AddColumn("Module", 16);
    AddColumn("Suspicious", 10);
}

void WDbgArkAnalyzeObjType::Analyze(const ExtRemoteTyped &ex_type_info, const ExtRemoteTyped &object) {
    ExtRemoteTyped obj_type_info = ex_type_info;

    try {
        PrintObjectDmlCmd(object);
        PrintFooter();

        auto result = m_obj_helper->GetObjectName(object);

        if ( SUCCEEDED(result.first) )
            AddTempWhiteList(result.second);

        WDbgArkAnalyzeBase* display = static_cast<WDbgArkAnalyzeBase*>(this);

        std::string parse_procedure_name("ParseProcedure");

        if ( obj_type_info.HasField("ObjectTypeFlags2") && obj_type_info.Field("UseExtendedParameters").GetUchar() & 1 )
            parse_procedure_name = "ParseProcedureEx";

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
    // width = 160
    AddColumn("Address", 18);
    AddColumn("CPU / Idx", 11);
    AddColumn("Symbol", 80);
    AddColumn("Module", 16);
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
        uint32_t limit = GetGDTLimit(gdt_entry);
        uint64_t address = 0ULL;

        if ( !NormalizeAddress(GetGDTBase(gdt_entry), &address) )
            err << wa::showminus << __FUNCTION__ << ": NormalizeAddress failed" << endlerr;

        std::stringstream addr_ext;

        if ( address ) {
            if ( g_Ext->IsCurMachine64() ) {
                if ( selector == KGDT64_SYS_TSS )
                    addr_ext << "<exec cmd=\"dt nt!_KTSS64 " << std::hex << std::showbase << address << "\">";
            } else {
                if ( selector == KGDT_TSS || selector == KGDT_DF_TSS || selector == KGDT_NMI_TSS )
                    addr_ext << "<exec cmd=\"dt nt!_KTSS " << std::hex << std::showbase << address << "\">";
                else if ( selector == KGDT_R0_PCR )
                    addr_ext << "<exec cmd=\"dt nt!_KPCR " << std::hex << std::showbase << address << "\">";
            }
        }

        addr_ext << std::internal << std::setw(18) << std::setfill('0') << std::hex << std::showbase << address;

        if ( address ) {
            if ( g_Ext->IsCurMachine64() ) {
                if ( selector == KGDT64_SYS_TSS )
                    addr_ext << "</exec>";
            } else {
                if ( selector == KGDT_TSS ||
                     selector == KGDT_DF_TSS ||
                     selector == KGDT_NMI_TSS ||
                     selector == KGDT_R0_PCR ) {
                     addr_ext << "</exec>";
                }
            }
        }

        std::stringstream selector_ext;
        selector_ext << std::hex << std::showbase << selector;

        std::stringstream limit_ext;
        limit_ext << std::internal << std::setw(10) << std::setfill('0') << std::hex << std::showbase << limit;

        std::stringstream dpl;
        dpl << std::dec << GetGDTDpl(gdt_entry);

        std::stringstream granularity;

        if ( IsGDTPageGranularity(gdt_entry) )
            granularity << "Page";
        else
            granularity << "Byte";

        std::stringstream present;

        if ( IsGDTFlagPresent(gdt_entry) )
            present << "P";
        else
            present << "NP";

        *this << addr_ext.str() << limit_ext.str() << cpu_idx << selector_ext.str();
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

    if ( g_Ext->IsCurMachine64() )
        field_name = "Bits.Granularity";
    else
        field_name = "HighWord.Bits.Granularity";

    return loc_gdt_entry.Field(field_name.c_str()).GetUlong() == 1;
}

bool WDbgArkAnalyzeGDT::IsGDTFlagPresent(const ExtRemoteTyped &gdt_entry) {
    ExtRemoteTyped loc_gdt_entry = gdt_entry;
    std::string field_name;

    if ( g_Ext->IsCurMachine64() )
        field_name = "Bits.Present";
    else
        field_name = "HighWord.Bits.Pres";

    return loc_gdt_entry.Field(field_name.c_str()).GetUlong() == 1;
}

uint32_t WDbgArkAnalyzeGDT::GetGDTDpl(const ExtRemoteTyped &gdt_entry) {
    ExtRemoteTyped loc_gdt_entry = gdt_entry;
    std::string field_name;

    if ( g_Ext->IsCurMachine64() )
        field_name = "Bits.Dpl";
    else
        field_name = "HighWord.Bits.Dpl";

    return loc_gdt_entry.Field(field_name.c_str()).GetUlong();
}

uint32_t WDbgArkAnalyzeGDT::GetGDTType(const ExtRemoteTyped &gdt_entry) {
    ExtRemoteTyped loc_gdt_entry = gdt_entry;
    std::string field_name;

    if ( g_Ext->IsCurMachine64() )
        field_name = "Bits.Type";
    else
        field_name = "HighWord.Bits.Type";

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

    if ( IsGDTPageGranularity(gdt_entry) )  // 4k segment
        limit = ((limit + 1) << PAGE_SHIFT) - 1;

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
    } catch ( const std::out_of_range& ) {}

    return selector_name;
}

std::string WDbgArkAnalyzeGDT::GetGDTTypeName(const ExtRemoteTyped &gdt_entry) {
    std::string type_name = "*UNKNOWN*";
    uint32_t type = GetGDTType(gdt_entry) & ~SEG_DESCTYPE(1);

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
    } catch ( const std::out_of_range& ) {}

    return type_name;
}
//////////////////////////////////////////////////////////////////////////
WDbgArkAnalyzeDriver::WDbgArkAnalyzeDriver(const std::shared_ptr<WDbgArkSymCache> &sym_cache)
    : WDbgArkAnalyzeBase(sym_cache) {
    // width = 180
    AddColumn("Address", 18);
    AddColumn("Name", 68);
    AddColumn("Symbol", 68);
    AddColumn("Module", 16);
    AddColumn("Suspicious", 10);
}

void WDbgArkAnalyzeDriver::Analyze(const ExtRemoteTyped &object) {
    ExtRemoteTyped& loc_object = const_cast<ExtRemoteTyped&>(object);

    try {
        PrintObjectDmlCmd(object);
        PrintFooter();

        WDbgArkAnalyzeBase* display = static_cast<WDbgArkAnalyzeBase*>(this);

        auto driver_start = loc_object.Field("DriverStart").GetPtr();
        uint32_t driver_size = loc_object.Field("DriverSize").GetUlong();

        if ( driver_start && driver_size )
            display->AddTempRangeWhiteList(driver_start, driver_size);

        auto result = m_obj_helper->GetObjectName(object);

        if ( SUCCEEDED(result.first) )
            AddTempWhiteList(result.second);

        out << wa::showplus << "Driver routines: " << endlout;
        PrintFooter();

        display->Analyze(loc_object.Field("DriverInit").GetPtr(), "DriverInit", "");
        display->Analyze(loc_object.Field("DriverStartIo").GetPtr(), "DriverStartIo", "");
        display->Analyze(loc_object.Field("DriverUnload").GetPtr(), "DriverUnload", "");

        if ( loc_object.Field("DriverExtension").GetPtr() )
            display->Analyze(loc_object.Field("DriverExtension").Field("AddDevice").GetPtr(), "AddDevice", "");

        PrintFooter();

        // display major table
        DisplayMajorTable(object);

        // display fast i/o table
        DisplayFastIo(object);

        // display FsFilterCallbacks
        DisplayFsFilterCallbacks(object);
    }
    catch(const ExtRemoteException &Ex) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    PrintFooter();
    InvalidateTempRanges();
}

void WDbgArkAnalyzeDriver::DisplayMajorTable(const ExtRemoteTyped &object) {
    WDbgArkAnalyzeBase* display = static_cast<WDbgArkAnalyzeBase*>(this);

    out << wa::showplus << "Major table routines: " << endlout;
    PrintFooter();

    auto major_table = WDbgArkDrvObjHelper(m_sym_cache, object).GetMajorTable();

    for ( auto &entry : major_table )
        display->Analyze(entry.first, entry.second, "");

    PrintFooter();
}

void WDbgArkAnalyzeDriver::DisplayFastIo(const ExtRemoteTyped &object) {
    WDbgArkAnalyzeBase* display = static_cast<WDbgArkAnalyzeBase*>(this);

    auto fast_io_table = WDbgArkDrvObjHelper(m_sym_cache, object).GetFastIoTable();

    if ( !fast_io_table.empty() ) {
        out << wa::showplus << "FastIO table routines: " << endlout;
        PrintFooter();

        for ( auto &entry : fast_io_table )
            display->Analyze(entry.first, entry.second, "");

        PrintFooter();
    }
}

void WDbgArkAnalyzeDriver::DisplayFsFilterCallbacks(const ExtRemoteTyped &object) {
    WDbgArkAnalyzeBase* display = static_cast<WDbgArkAnalyzeBase*>(this);

    auto fs_cb_table = WDbgArkDrvObjHelper(m_sym_cache, object).GetFsFilterCbTable();

    if ( !fs_cb_table.empty() ) {
        out << wa::showplus << "FsFilterCallbacks table routines: " << endlout;
        PrintFooter();

        for ( auto &entry : fs_cb_table )
            display->Analyze(entry.first, entry.second, "");

        PrintFooter();
    }
}
//////////////////////////////////////////////////////////////////////////

}   // namespace wa
