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
#include <set>

#include "manipulators.hpp"

namespace wa {
//////////////////////////////////////////////////////////////////////////
// helpers
//////////////////////////////////////////////////////////////////////////
std::pair<HRESULT, std::string> GetNameByOffset(const unsigned __int64 address);
HRESULT GetModuleNames(const unsigned __int64 address,
                       std::string* image_name,
                       std::string* module_name,
                       std::string* loaded_image_name);
//////////////////////////////////////////////////////////////////////////
// white list range
//////////////////////////////////////////////////////////////////////////
class WDbgArkAnalyzeWhiteList {
 public:
    typedef std::pair<unsigned __int64, unsigned __int64> Range;    // start, end
    typedef std::set<Range> Ranges;

    WDbgArkAnalyzeWhiteList() : m_ranges(), err() {}

    void AddRangeWhiteList(const unsigned __int64 start, const unsigned __int64 end) {
        m_ranges.insert(std::make_pair(start, end));
    }

    void AddRangeWhiteList(const unsigned __int64 start, const unsigned __int32 size) {
        m_ranges.insert(std::make_pair(start, start + size));
    }

    bool AddRangeWhiteList(const std::string &module_name);
    bool AddSymbolWhiteList(const std::string &symbol_name, const unsigned __int32 size);
    bool IsAddressInWhiteList(const unsigned __int64 address) const;

 private:
    Ranges m_ranges;
    std::stringstream err;
};
//////////////////////////////////////////////////////////////////////////
// analyze, display, print routines
//////////////////////////////////////////////////////////////////////////
class WDbgArkAnalyzeBase: public WDbgArkAnalyzeWhiteList {
 public:
    enum class AnalyzeType {
        AnalyzeTypeDefault,
        AnalyzeTypeCallback,
        AnalyzeTypeObjType,
        AnalyzeTypeIDT,
        AnalyzeTypeGDT
    };

    WDbgArkAnalyzeBase() : bprinter_out(),
                           tp(new bprinter::TablePrinter(&bprinter_out)) {}
    virtual ~WDbgArkAnalyzeBase() {}
    static std::unique_ptr<WDbgArkAnalyzeBase> Create(const AnalyzeType type = AnalyzeType::AnalyzeTypeDefault);

    //////////////////////////////////////////////////////////////////////////
    // brinter routines
    //////////////////////////////////////////////////////////////////////////
    virtual void PrintHeader(void) { tp->PrintHeader(); }
    virtual void PrintFooter(void) { tp->PrintFooter(); }
    virtual void AddColumn(const std::string &header_name, const int column_width) {
        tp->AddColumn(header_name, column_width);
    }
    virtual void StringToTable(const std::string &what) { *tp << what; }
    virtual void FlushOut(void) { tp->flush_out(); }
    virtual void FlushWarn(void) { tp->flush_warn(); }
    virtual void FlushErr(void) { tp->flush_err(); }
    virtual void PrintObjectDmlCmd(const ExtRemoteTyped &object);

    //////////////////////////////////////////////////////////////////////////
    // analyze routines
    //////////////////////////////////////////////////////////////////////////
    virtual bool IsSuspiciousAddress(const unsigned __int64 address) const;
    virtual void Analyze(const unsigned __int64 address, const std::string &type, const std::string &additional_info);
    virtual void Analyze(const ExtRemoteTyped &ex_type_info, const ExtRemoteTyped &object) {
        std::stringstream err;
        err << __FUNCTION__ << ": unimplemented" << endlerr;
    }
    virtual void Analyze(const ExtRemoteTyped &gdt_entry,
                         const std::string &cpu_idx,
                         const unsigned __int32 selector,
                         const std::string &additional_info) {
        std::stringstream err;
        err << __FUNCTION__ << ": unimplemented" << endlerr;
    }

 private:
    std::stringstream bprinter_out;
    std::unique_ptr<bprinter::TablePrinter> tp;
};
//////////////////////////////////////////////////////////////////////////
class WDbgArkAnalyzeDefault: public WDbgArkAnalyzeBase {
 public:
    WDbgArkAnalyzeDefault();
    virtual ~WDbgArkAnalyzeDefault() {}

 private:
    std::stringstream out;
    std::stringstream warn;
    std::stringstream err;
};
//////////////////////////////////////////////////////////////////////////
class WDbgArkAnalyzeCallback: public WDbgArkAnalyzeBase {
 public:
    WDbgArkAnalyzeCallback();
    virtual ~WDbgArkAnalyzeCallback() {}

 private:
    std::stringstream out;
    std::stringstream warn;
    std::stringstream err;
};
//////////////////////////////////////////////////////////////////////////
class WDbgArkAnalyzeObjType: public WDbgArkAnalyzeBase {
 public:
    WDbgArkAnalyzeObjType();
    virtual ~WDbgArkAnalyzeObjType() {}

    virtual void Analyze(const ExtRemoteTyped &ex_type_info, const ExtRemoteTyped &object);

 private:
    std::stringstream out;
    std::stringstream warn;
    std::stringstream err;
};
//////////////////////////////////////////////////////////////////////////
class WDbgArkAnalyzeIDT: public WDbgArkAnalyzeBase {
 public:
    WDbgArkAnalyzeIDT();
    virtual ~WDbgArkAnalyzeIDT() {}

 private:
    std::stringstream out;
    std::stringstream warn;
    std::stringstream err;
};
//////////////////////////////////////////////////////////////////////////
class WDbgArkAnalyzeGDT: public WDbgArkAnalyzeBase {
 public:
    WDbgArkAnalyzeGDT();
    virtual ~WDbgArkAnalyzeGDT() {}

    virtual void Analyze(const ExtRemoteTyped &gdt_entry,
                         const std::string &cpu_idx,
                         const unsigned __int32 selector,
                         const std::string &additional_info);

 private:
    std::stringstream out;
    std::stringstream warn;
    std::stringstream err;

    std::string GetGDTSelectorName(const unsigned __int32 selector) const;
    unsigned __int32 GetGDTType(const ExtRemoteTyped &gdt_entry);
    std::string GetGDTTypeName(const ExtRemoteTyped &gdt_entry);
    unsigned __int32 GetGDTLimit(const ExtRemoteTyped &gdt_entry);
    unsigned __int64 GetGDTBase(const ExtRemoteTyped &gdt_entry);
    bool IsGDTPageGranularity(const ExtRemoteTyped &gdt_entry);
    bool IsGDTFlagPresent(const ExtRemoteTyped &gdt_entry);
    bool IsGDTTypeSystem(const ExtRemoteTyped &gdt_entry);
    unsigned __int32 GetGDTDpl(const ExtRemoteTyped &gdt_entry);
};
//////////////////////////////////////////////////////////////////////////
}   // namespace wa

#endif  // ANALYZE_HPP_
