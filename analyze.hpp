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

//////////////////////////////////////////////////////////////////////////
//  Include this after "#define EXT_CLASS WDbgArk" only
//////////////////////////////////////////////////////////////////////////

#if _MSC_VER > 1000
#pragma once
#endif

#ifndef ANALYZE_HPP_
#define ANALYZE_HPP_

#include <engextcpp.hpp>
#include <bprinter/table_printer.h>

#include <string>
#include <sstream>
#include <memory>
#include <utility>

#include "objhelper.hpp"

//////////////////////////////////////////////////////////////////////////
// analyze, display, print routines
//////////////////////////////////////////////////////////////////////////
class WDbgArkAnalyze {
 public:
     enum AnalyzeTypeInit {
         AnalyzeTypeDefault,
         AnalyzeTypeCallback,
         AnalyzeTypeIDT,
         AnalyzeTypeGDT
     };

    WDbgArkAnalyze();
    explicit WDbgArkAnalyze(const AnalyzeTypeInit type);
    ~WDbgArkAnalyze() {}

    bool IsInited(void) const { return m_inited; }

    //////////////////////////////////////////////////////////////////////////
    // brinter routines
    //////////////////////////////////////////////////////////////////////////
    void PrintHeader(void) { if ( IsInited() ) tp->PrintHeader(); }
    void PrintFooter(void) { if ( IsInited() ) tp->PrintFooter(); }
    void AddColumn(const std::string &header_name, const int column_width) {
        if ( IsInited() )
            tp->AddColumn(header_name, column_width);
    }
    void StreamToTable(const std::string &what) { if ( IsInited() ) *tp << what; }
    void FlushOut(void) { if ( IsInited() ) tp->flush_out(); }
    void FlushWarn(void) { if ( IsInited() ) tp->flush_warn(); }
    void FlushErr(void) { if ( IsInited() ) tp->flush_err(); }
    void PrintObjectDmlCmd(const ExtRemoteTyped &object);

    //////////////////////////////////////////////////////////////////////////
    // owner module routines
    //////////////////////////////////////////////////////////////////////////
    bool SetOwnerModule(void) {
        m_owner_module_start = 0ULL;
        m_owner_module_end = 0ULL;
        m_owner_module_inited = false;

        return false;
    }

    bool SetOwnerModule(const unsigned __int64 mod_start, const unsigned __int64 mod_end) {
        if ( !mod_start || !mod_end )
            return false;

        m_owner_module_start = mod_start;
        m_owner_module_end = mod_end;
        m_owner_module_inited = true;

        return true;
    }

    bool SetOwnerModule(const std::string &module_name);

    //////////////////////////////////////////////////////////////////////////
    // analyze routines
    //////////////////////////////////////////////////////////////////////////
    void AnalyzeAddressAsRoutine(const unsigned __int64 address,
                                 const std::string &type,
                                 const std::string &additional_info);

    void AnalyzeObjectTypeInfo(const ExtRemoteTyped &ex_type_info, const ExtRemoteTyped &object);

    void AnalyzeGDTEntry(const ExtRemoteTyped &gdt_entry,
                         const std::string &cpu_idx,
                         const unsigned __int32 selector,
                         const std::string &additional_info);

 private:
    bool             m_inited;
    bool             m_owner_module_inited;
    unsigned __int64 m_owner_module_start;
    unsigned __int64 m_owner_module_end;

    std::unique_ptr<bprinter::TablePrinter> tp;
    std::unique_ptr<WDbgArkObjHelper>       m_obj_helper;
    //////////////////////////////////////////////////////////////////////////
    // helpers
    //////////////////////////////////////////////////////////////////////////
    HRESULT GetModuleNames(const unsigned __int64 address,
                           std::string* image_name,
                           std::string* module_name,
                           std::string* loaded_image_name);

    std::pair<HRESULT, std::string> GetNameByOffset(const unsigned __int64 address);

    bool        IsSuspiciousAddress(const unsigned __int64 address) const;
    std::string GetGDTSelectorName(const unsigned __int32 selector) const;

    //////////////////////////////////////////////////////////////////////////
    // output streams
    //////////////////////////////////////////////////////////////////////////
    std::stringstream out;
    std::stringstream warn;
    std::stringstream err;
    std::stringstream bprinter_out;
};

#endif  // ANALYZE_HPP_
