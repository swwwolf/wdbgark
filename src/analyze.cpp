/*
    * WinDBG Anti-RootKit extension
    * Copyright © 2013-2015  Vyacheslav Rusakoff
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
#include <dbghelp.h>

#include <string>
#include <algorithm>
#include <utility>
#include <memory>

#include "strings.hpp"
#include "symbols.hpp"
#include "./ddk.h"

namespace wa {
//////////////////////////////////////////////////////////////////////////
bool WDbgArkAnalyzeWhiteList::AddRangeWhiteListInternal(const std::string &module_name, Ranges* ranges) {
    try {
        unsigned __int64 module_start = 0;
        HRESULT result = g_Ext->m_Symbols3->GetModuleByModuleName2(module_name.c_str(),
                                                                   0UL,
                                                                   0UL,
                                                                   nullptr,
                                                                   &module_start);

        if ( SUCCEEDED(result) ) {
            IMAGEHLP_MODULEW64 info;
            g_Ext->GetModuleImagehlpInfo(module_start, &info);
            ranges->insert(std::make_pair(module_start, module_start + info.ImageSize));
            return true;
        }
    }
    catch ( const ExtStatusException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    return false;
}

bool WDbgArkAnalyzeWhiteList::AddSymbolWhiteListInternal(const std::string &symbol_name,
                                                         const unsigned __int32 size,
                                                         Ranges* ranges) {
    unsigned __int64 symbol_offset = 0;

    if ( !m_sym_cache->GetSymbolOffset(symbol_name, true, &symbol_offset) )
        return false;

    ranges->insert(std::make_pair(symbol_offset, symbol_offset + size));
    return true;
}

void WDbgArkAnalyzeWhiteList::AddTempWhiteList(const std::string &name) {
    try {
        if ( !m_wl_entries.empty() ) {
            std::string search_name = name;
            std::transform(search_name.begin(), search_name.end(), search_name.begin(), tolower);

            auto entry_list = m_wl_entries.at(search_name);

            for ( auto entry : entry_list )
                AddTempRangeWhiteList(entry);
        }
    } catch ( const std::out_of_range& ) {}
}

bool WDbgArkAnalyzeWhiteList::IsAddressInWhiteList(const unsigned __int64 address) const {
    if ( m_ranges.empty() && m_temp_ranges.empty() )
        return true;

    Ranges::iterator it = std::find_if(m_ranges.begin(),
                                       m_ranges.end(),
                                       [address](const Range &range) {
                                           return ((address >= range.first) && (address <= range.second)); });

    if ( it != m_ranges.end() )
        return true;

    Ranges::iterator temp_it = std::find_if(m_temp_ranges.begin(),
                                            m_temp_ranges.end(),
                                            [address](const Range &range) {
                                                return ((address >= range.first) && (address <= range.second)); });

    if ( temp_it != m_temp_ranges.end() )
        return true;

    return false;
}
//////////////////////////////////////////////////////////////////////////
std::unique_ptr<WDbgArkAnalyzeBase> WDbgArkAnalyzeBase::Create(const std::shared_ptr<WDbgArkSymCache> &sym_cache,
                                                               const AnalyzeType type) {
    switch ( type ) {
        case AnalyzeType::AnalyzeTypeCallback:
            return std::unique_ptr<WDbgArkAnalyzeBase>(new WDbgArkAnalyzeCallback(sym_cache));
        break;

        case AnalyzeType::AnalyzeTypeObjType:
            return std::unique_ptr<WDbgArkAnalyzeBase>(new WDbgArkAnalyzeObjType(sym_cache));
        break;

        case AnalyzeType::AnalyzeTypeIDT:
            return std::unique_ptr<WDbgArkAnalyzeBase>(new WDbgArkAnalyzeIDT(sym_cache));
        break;

        case AnalyzeType::AnalyzeTypeGDT:
            return std::unique_ptr<WDbgArkAnalyzeBase>(new WDbgArkAnalyzeGDT(sym_cache));
        break;

        case AnalyzeType::AnalyzeTypeDriver:
            return std::unique_ptr<WDbgArkAnalyzeBase>(new WDbgArkAnalyzeDriver(sym_cache));
        break;

        case AnalyzeType::AnalyzeTypeDefault:
        default:
            return std::unique_ptr<WDbgArkAnalyzeBase>(new WDbgArkAnalyzeDefault(sym_cache));
        break;
    }
}

bool WDbgArkAnalyzeBase::IsSuspiciousAddress(const unsigned __int64 address) const {
    if ( !address )
        return false;

    if ( IsAddressInWhiteList(address) )
        return false;

    return true;
}

void WDbgArkAnalyzeBase::Analyze(const unsigned __int64 address,
                                 const std::string &type,
                                 const std::string &additional_info) {
    std::string       symbol_name;
    std::string       module_name;
    std::string       image_name;
    std::string       loaded_image_name;
    std::stringstream module_command_buf;

    bool suspicious = IsSuspiciousAddress(address);

    if ( address ) {
        symbol_name = "*UNKNOWN*";
        module_name = "*UNKNOWN*";

        WDbgArkSymbolsBase symbols_base;
        if ( !SUCCEEDED(symbols_base.GetModuleNames(address, &image_name, &module_name, &loaded_image_name)) )
            suspicious = true;

        module_command_buf << "<exec cmd=\"lmvm " << module_name << "\">" << std::setw(16) << module_name << "</exec>";

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

        display->Analyze(obj_type_info.Field("DumpProcedure").GetPtr(), "DumpProcedure", "");
        display->Analyze(obj_type_info.Field("OpenProcedure").GetPtr(), "OpenProcedure", "");
        display->Analyze(obj_type_info.Field("CloseProcedure").GetPtr(), "CloseProcedure", "");
        display->Analyze(obj_type_info.Field("DeleteProcedure").GetPtr(), "DeleteProcedure", "");
        display->Analyze(obj_type_info.Field("ParseProcedure").GetPtr(), "ParseProcedure", "");
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
    : WDbgArkAnalyzeBase(sym_cache),
      err() {
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
                                const unsigned __int32 selector,
                                const std::string &additional_info) {
    try {
        unsigned __int64 address = GetGDTBase(gdt_entry);
        unsigned __int32 limit = GetGDTLimit(gdt_entry);

        std::stringstream expression;
        expression << std::hex << std::showbase <<  address;
        address = g_Ext->EvalExprU64(expression.str().c_str());

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

unsigned __int32 WDbgArkAnalyzeGDT::GetGDTDpl(const ExtRemoteTyped &gdt_entry) {
    ExtRemoteTyped loc_gdt_entry = gdt_entry;
    std::string field_name;

    if ( g_Ext->IsCurMachine64() )
        field_name = "Bits.Dpl";
    else
        field_name = "HighWord.Bits.Dpl";

    return loc_gdt_entry.Field(field_name.c_str()).GetUlong();
}

unsigned __int32 WDbgArkAnalyzeGDT::GetGDTType(const ExtRemoteTyped &gdt_entry) {
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

unsigned __int32 WDbgArkAnalyzeGDT::GetGDTLimit(const ExtRemoteTyped &gdt_entry) {
    ExtRemoteTyped   loc_gdt_entry = gdt_entry;
    unsigned __int32 limit         = 0;

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

unsigned __int64 WDbgArkAnalyzeGDT::GetGDTBase(const ExtRemoteTyped &gdt_entry) {
    ExtRemoteTyped   loc_gdt_entry = gdt_entry;
    unsigned __int64 base          = 0;

    if ( g_Ext->IsCurMachine64() ) {
        base =\
            (static_cast<unsigned __int64>(loc_gdt_entry.Field("BaseLow").GetUshort())) |\
            (static_cast<unsigned __int64>(loc_gdt_entry.Field("Bytes.BaseMiddle").GetUchar()) << 16) |\
            (static_cast<unsigned __int64>(loc_gdt_entry.Field("Bytes.BaseHigh").GetUchar()) << 24) |\
            (static_cast<unsigned __int64>(loc_gdt_entry.Field("BaseUpper").GetUlong()) << 32);
    } else {
        base =\
            (static_cast<unsigned __int64>(loc_gdt_entry.Field("BaseLow").GetUshort())) |\
            (static_cast<unsigned __int64>(loc_gdt_entry.Field("HighWord.Bytes.BaseMid").GetUchar()) << 16) |\
            (static_cast<unsigned __int64>(loc_gdt_entry.Field("HighWord.Bytes.BaseHi").GetUchar()) << 24);
    }

    return base;
}

std::string WDbgArkAnalyzeGDT::GetGDTSelectorName(const unsigned __int32 selector) const {
    if ( g_Ext->IsCurMachine64() ) {
        switch ( selector ) {
            case KGDT64_NULL:
                return make_string( KGDT64_NULL );

            case KGDT64_R0_CODE:
                return make_string( KGDT64_R0_CODE );

            case KGDT64_R0_DATA:
                return make_string( KGDT64_R0_DATA );

            case KGDT64_R3_CMCODE:
                return make_string( KGDT64_R3_CMCODE );

            case KGDT64_R3_DATA:
                return make_string( KGDT64_R3_DATA );

            case KGDT64_R3_CODE:
                return make_string( KGDT64_R3_CODE );

            case KGDT64_SYS_TSS:
                return make_string( KGDT64_SYS_TSS );

            case KGDT64_R3_CMTEB:
                return make_string( KGDT64_R3_CMTEB );

            default:
                return "*RESERVED*";
        }
    } else {
        switch ( selector ) {
            case KGDT_R0_CODE:
                return make_string( KGDT_R0_CODE );

            case KGDT_R0_DATA:
                return make_string( KGDT_R0_DATA );

            case KGDT_R3_CODE:
                return make_string( KGDT_R3_CODE );

            case KGDT_R3_DATA:
                return make_string( KGDT_R3_DATA );

            case KGDT_TSS:
                return make_string( KGDT_TSS );

            case KGDT_R0_PCR:
                return make_string( KGDT_R0_PCR );

            case KGDT_R3_TEB:
                return make_string( KGDT_R3_TEB );

            case KGDT_LDT:
                return make_string( KGDT_LDT );

            case KGDT_DF_TSS:
                return make_string( KGDT_DF_TSS );

            case KGDT_NMI_TSS:
                return make_string( KGDT_NMI_TSS );

            case KGDT_GDT_ALIAS:
                return make_string( KGDT_GDT_ALIAS );

            case KGDT_CDA16:
                return make_string( KGDT_CDA16 );

            case KGDT_CODE16:
                return make_string( KGDT_CODE16 );

            case KGDT_STACK16:
                return make_string( KGDT_STACK16 );

            default:
                return "*RESERVED*";
        }
    }
}

// TODO(swwwolf): map
std::string WDbgArkAnalyzeGDT::GetGDTTypeName(const ExtRemoteTyped &gdt_entry) {
    unsigned __int32 type = GetGDTType(gdt_entry) & ~SEG_DESCTYPE(1);

    if ( IsGDTTypeSystem(gdt_entry) ) {
        if ( g_Ext->IsCurMachine64() ) {    // system, x64
            switch ( type ) {
                case SEG_SYS_UPPER_8_BYTE:
                    return make_string(SEG_SYS_UPPER_8_BYTE);

                case SEG_SYS_RESERVED_1:
                    return make_string(SEG_SYS_RESERVED_1);

                case SEG_SYS_LDT:
                    return make_string(SEG_SYS_LDT);

                case SEG_SYS_RESERVED_3:
                    return make_string(SEG_SYS_RESERVED_3);

                case SEG_SYS_RESERVED_4:
                    return make_string(SEG_SYS_RESERVED_4);

                case SEG_SYS_RESERVED_5:
                    return make_string(SEG_SYS_RESERVED_5);

                case SEG_SYS_RESERVED_6:
                    return make_string(SEG_SYS_RESERVED_6);

                case SEG_SYS_RESERVED_7:
                    return make_string(SEG_SYS_RESERVED_7);

                case SEG_SYS_RESERVED_8:
                    return make_string(SEG_SYS_RESERVED_8);

                case SEG_SYS_TSS64_AVL:
                    return make_string(SEG_SYS_TSS64_AVL);

                case SEG_SYS_RESERVED_10:
                    return make_string(SEG_SYS_RESERVED_10);

                case SEG_SYS_TSS64_BUSY:
                    return make_string(SEG_SYS_TSS64_BUSY);

                case SEG_SYS_CALLGATE_64:
                    return make_string(SEG_SYS_CALLGATE_64);

                case SEG_SYS_RESERVED_13:
                    return make_string(SEG_SYS_RESERVED_13);

                case SEG_SYS_INT_GATE_64:
                    return make_string(SEG_SYS_INT_GATE_64);

                case SEG_SYS_TRAP_GATE_64:
                    return make_string(SEG_SYS_TRAP_GATE_64);
                default:
                    return "*UNKNOWN*";
            }
        } else {    // system, x86
            switch ( type ) {
                case SEG_SYS_RESERVED_0:
                    return make_string(SEG_SYS_RESERVED_0);

                case SEG_SYS_TSS16_AVL:
                    return make_string(SEG_SYS_TSS16_AVL);

                case SEG_SYS_LDT:
                    return make_string(SEG_SYS_LDT);

                case SEG_SYS_TSS16_BUSY:
                    return make_string(SEG_SYS_TSS16_BUSY);

                case SEG_SYS_CALLGATE_16:
                    return make_string(SEG_SYS_CALLGATE_16);

                case SEG_SYS_TASKGATE:
                    return make_string(SEG_SYS_TASKGATE);

                case SEG_SYS_INT_GATE_16:
                    return make_string(SEG_SYS_INT_GATE_16);

                case SEG_SYS_TRAP_GATE_16:
                    return make_string(SEG_SYS_TRAP_GATE_16);

                case SEG_SYS_RESERVED_8:
                    return make_string(SEG_SYS_RESERVED_8);

                case SEG_SYS_TSS32_AVL:
                    return make_string(SEG_SYS_TSS32_AVL);

                case SEG_SYS_RESERVED_10:
                    return make_string(SEG_SYS_RESERVED_10);

                case SEG_SYS_TSS32_BUSY:
                    return make_string(SEG_SYS_TSS32_BUSY);

                case SEG_SYS_CALLGATE_32:
                    return make_string(SEG_SYS_CALLGATE_32);

                case SEG_SYS_RESERVED_13:
                    return make_string(SEG_SYS_RESERVED_13);

                case SEG_SYS_INT_GATE_32:
                    return make_string(SEG_SYS_INT_GATE_32);

                case SEG_SYS_TRAP_GATE_32:
                    return make_string(SEG_SYS_TRAP_GATE_32);
                default:
                    return "*UNKNOWN*";
            }
        }
    } else {    // Code/Data x86/x64
        switch ( type ) {
            case SEG_DATA_RD:
                return make_string(SEG_DATA_RD);

            case SEG_DATA_RDA:
                return make_string(SEG_DATA_RDA);

            case SEG_DATA_RDWR:
                return make_string(SEG_DATA_RDWR);

            case SEG_DATA_RDWRA:
                return make_string(SEG_DATA_RDWRA);

            case SEG_DATA_RDEXPD:
                return make_string(SEG_DATA_RDEXPD);

            case SEG_DATA_RDEXPDA:
                return make_string(SEG_DATA_RDEXPDA);

            case SEG_DATA_RDWREXPD:
                return make_string(SEG_DATA_RDWREXPD);

            case SEG_DATA_RDWREXPDA:
                return make_string(SEG_DATA_RDWREXPDA);

            case SEG_CODE_EX:
                return make_string(SEG_CODE_EX);

            case SEG_CODE_EXA:
                return make_string(SEG_CODE_EXA);

            case SEG_CODE_EXRD:
                return make_string(SEG_CODE_EXRD);

            case SEG_CODE_EXRDA:
                return make_string(SEG_CODE_EXRDA);

            case SEG_CODE_EXC:
                return make_string(SEG_CODE_EXC);

            case SEG_CODE_EXCA:
                return make_string(SEG_CODE_EXCA);

            case SEG_CODE_EXRDC:
                return make_string(SEG_CODE_EXRDC);

            case SEG_CODE_EXRDCA:
                return make_string(SEG_CODE_EXRDCA);
            default:
                return "*UNKNOWN*";
        }
    }
}
//////////////////////////////////////////////////////////////////////////
WDbgArkAnalyzeDriver::WDbgArkAnalyzeDriver(const std::shared_ptr<WDbgArkSymCache> &sym_cache)
    : WDbgArkAnalyzeBase(sym_cache),
      m_major_table_name(),
      m_fast_io_table_name(),
      m_fs_filter_cb_table_name(),
      out(),
      warn(),
      err() {
    // width = 180
    AddColumn("Address", 18);
    AddColumn("Name", 68);
    AddColumn("Symbol", 68);
    AddColumn("Module", 16);
    AddColumn("Suspicious", 10);

    m_major_table_name.push_back(make_string(IRP_MJ_CREATE));
    m_major_table_name.push_back(make_string(IRP_MJ_CREATE_NAMED_PIPE));
    m_major_table_name.push_back(make_string(IRP_MJ_CLOSE));
    m_major_table_name.push_back(make_string(IRP_MJ_READ));
    m_major_table_name.push_back(make_string(IRP_MJ_WRITE));
    m_major_table_name.push_back(make_string(IRP_MJ_QUERY_INFORMATION));
    m_major_table_name.push_back(make_string(IRP_MJ_SET_INFORMATION));
    m_major_table_name.push_back(make_string(IRP_MJ_QUERY_EA));
    m_major_table_name.push_back(make_string(IRP_MJ_SET_EA));
    m_major_table_name.push_back(make_string(IRP_MJ_FLUSH_BUFFERS));
    m_major_table_name.push_back(make_string(IRP_MJ_QUERY_VOLUME_INFORMATION));
    m_major_table_name.push_back(make_string(IRP_MJ_SET_VOLUME_INFORMATION));
    m_major_table_name.push_back(make_string(IRP_MJ_DIRECTORY_CONTROL));
    m_major_table_name.push_back(make_string(IRP_MJ_FILE_SYSTEM_CONTROL));
    m_major_table_name.push_back(make_string(IRP_MJ_DEVICE_CONTROL));
    m_major_table_name.push_back(make_string(IRP_MJ_INTERNAL_DEVICE_CONTROL));
    m_major_table_name.push_back(make_string(IRP_MJ_SHUTDOWN));
    m_major_table_name.push_back(make_string(IRP_MJ_LOCK_CONTROL));
    m_major_table_name.push_back(make_string(IRP_MJ_CLEANUP));
    m_major_table_name.push_back(make_string(IRP_MJ_CREATE_MAILSLOT));
    m_major_table_name.push_back(make_string(IRP_MJ_QUERY_SECURITY));
    m_major_table_name.push_back(make_string(IRP_MJ_SET_SECURITY));
    m_major_table_name.push_back(make_string(IRP_MJ_POWER));
    m_major_table_name.push_back(make_string(IRP_MJ_SYSTEM_CONTROL));
    m_major_table_name.push_back(make_string(IRP_MJ_DEVICE_CHANGE));
    m_major_table_name.push_back(make_string(IRP_MJ_QUERY_QUOTA));
    m_major_table_name.push_back(make_string(IRP_MJ_SET_QUOTA));
    m_major_table_name.push_back(make_string(IRP_MJ_PNP));

    m_fast_io_table_name.push_back(make_string(FastIoCheckIfPossible));
    m_fast_io_table_name.push_back(make_string(FastIoRead));
    m_fast_io_table_name.push_back(make_string(FastIoWrite));
    m_fast_io_table_name.push_back(make_string(FastIoQueryBasicInfo));
    m_fast_io_table_name.push_back(make_string(FastIoQueryStandardInfo));
    m_fast_io_table_name.push_back(make_string(FastIoLock));
    m_fast_io_table_name.push_back(make_string(FastIoUnlockSingle));
    m_fast_io_table_name.push_back(make_string(FastIoUnlockAll));
    m_fast_io_table_name.push_back(make_string(FastIoUnlockAllByKey));
    m_fast_io_table_name.push_back(make_string(FastIoDeviceControl));
    m_fast_io_table_name.push_back(make_string(AcquireFileForNtCreateSection));
    m_fast_io_table_name.push_back(make_string(ReleaseFileForNtCreateSection));
    m_fast_io_table_name.push_back(make_string(FastIoDetachDevice));
    m_fast_io_table_name.push_back(make_string(FastIoQueryNetworkOpenInfo));
    m_fast_io_table_name.push_back(make_string(AcquireForModWrite));
    m_fast_io_table_name.push_back(make_string(MdlRead));
    m_fast_io_table_name.push_back(make_string(MdlReadComplete));
    m_fast_io_table_name.push_back(make_string(PrepareMdlWrite));
    m_fast_io_table_name.push_back(make_string(MdlWriteComplete));
    m_fast_io_table_name.push_back(make_string(FastIoReadCompressed));
    m_fast_io_table_name.push_back(make_string(FastIoWriteCompressed));
    m_fast_io_table_name.push_back(make_string(MdlReadCompleteCompressed));
    m_fast_io_table_name.push_back(make_string(MdlWriteCompleteCompressed));
    m_fast_io_table_name.push_back(make_string(FastIoQueryOpen));
    m_fast_io_table_name.push_back(make_string(ReleaseForModWrite));
    m_fast_io_table_name.push_back(make_string(AcquireForCcFlush));
    m_fast_io_table_name.push_back(make_string(ReleaseForCcFlush));

    m_fs_filter_cb_table_name.push_back(make_string(PreAcquireForSectionSynchronization));
    m_fs_filter_cb_table_name.push_back(make_string(PostAcquireForSectionSynchronization));
    m_fs_filter_cb_table_name.push_back(make_string(PreReleaseForSectionSynchronization));
    m_fs_filter_cb_table_name.push_back(make_string(PostReleaseForSectionSynchronization));
    m_fs_filter_cb_table_name.push_back(make_string(PreAcquireForCcFlush));
    m_fs_filter_cb_table_name.push_back(make_string(PostAcquireForCcFlush));
    m_fs_filter_cb_table_name.push_back(make_string(PreReleaseForCcFlush));
    m_fs_filter_cb_table_name.push_back(make_string(PostReleaseForCcFlush));
    m_fs_filter_cb_table_name.push_back(make_string(PreAcquireForModifiedPageWriter));
    m_fs_filter_cb_table_name.push_back(make_string(PostAcquireForModifiedPageWriter));
    m_fs_filter_cb_table_name.push_back(make_string(PreReleaseForModifiedPageWriter));
    m_fs_filter_cb_table_name.push_back(make_string(PostReleaseForModifiedPageWriter));
}

void WDbgArkAnalyzeDriver::Analyze(const ExtRemoteTyped &object) {
    ExtRemoteTyped loc_object = object;

    try {
        PrintObjectDmlCmd(object);
        PrintFooter();

        WDbgArkAnalyzeBase* display = static_cast<WDbgArkAnalyzeBase*>(this);

        auto driver_start = loc_object.Field("DriverStart").GetPtr();
        unsigned __int32 driver_size = loc_object.Field("DriverSize").GetUlong();

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
    ExtRemoteTyped loc_object = object;
    WDbgArkAnalyzeBase* display = static_cast<WDbgArkAnalyzeBase*>(this);

    out << wa::showplus << "Major table routines: " << endlout;
    PrintFooter();

    ExtRemoteTyped major_table = loc_object.Field("MajorFunction");

    for ( unsigned long i = 0; i < m_major_table_name.size(); i++ )
        display->Analyze(major_table[i].GetPtr(), m_major_table_name.at(i), "");

    PrintFooter();
}

void WDbgArkAnalyzeDriver::DisplayFastIo(const ExtRemoteTyped &object) {
    ExtRemoteTyped loc_object = object;
    WDbgArkAnalyzeBase* display = static_cast<WDbgArkAnalyzeBase*>(this);

    ExtRemoteTyped fast_io_dispatch = loc_object.Field("FastIoDispatch");
    auto fast_io_dispatch_ptr = fast_io_dispatch.GetPtr();

    if ( fast_io_dispatch_ptr ) {
        out << wa::showplus << "FastIO table routines: " << endlout;
        PrintFooter();

        fast_io_dispatch_ptr += fast_io_dispatch.GetFieldOffset("FastIoCheckIfPossible");

        for ( unsigned __int32 i = 0; i < m_fast_io_table_name.size(); i++ ) {
            ExtRemoteData fast_io_dispatch_data(fast_io_dispatch_ptr + i * g_Ext->m_PtrSize, g_Ext->m_PtrSize);
            display->Analyze(fast_io_dispatch_data.GetPtr(), m_fast_io_table_name.at(i), "");
        }

        PrintFooter();
    }
}

void WDbgArkAnalyzeDriver::DisplayFsFilterCallbacks(const ExtRemoteTyped &object) {
    ExtRemoteTyped loc_object = object;
    WDbgArkAnalyzeBase* display = static_cast<WDbgArkAnalyzeBase*>(this);

    if ( loc_object.Field("DriverExtension").GetPtr() ) {
        ExtRemoteTyped fs_filter_callbacks = loc_object.Field("DriverExtension").Field("FsFilterCallbacks");
        auto fs_filter_callbacks_ptr = fs_filter_callbacks.GetPtr();

        if ( fs_filter_callbacks_ptr ) {
            out << wa::showplus << "FsFilterCallbacks table routines: " << endlout;
            PrintFooter();

            fs_filter_callbacks_ptr += fs_filter_callbacks.GetFieldOffset("PreAcquireForSectionSynchronization");

            for ( unsigned __int32 i = 0; i < m_fs_filter_cb_table_name.size(); i++ ) {
                ExtRemoteData fs_filter_callbacks_data(fs_filter_callbacks_ptr + i * g_Ext->m_PtrSize,
                                                       g_Ext->m_PtrSize);
                display->Analyze(fs_filter_callbacks_data.GetPtr(), m_fs_filter_cb_table_name.at(i), "");
            }

            PrintFooter();
        }
    }
}
//////////////////////////////////////////////////////////////////////////

}   // namespace wa
