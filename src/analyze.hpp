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
#include <vector>

#include "manipulators.hpp"
#include "objhelper.hpp"
#include "symcache.hpp"

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
    using Range = std::pair<unsigned __int64, unsigned __int64>;    // start, end
    using Ranges = std::set<Range>;

    explicit WDbgArkAnalyzeWhiteList(const std::shared_ptr<WDbgArkSymCache> &sym_cache)
        : m_ranges(),
          m_sym_cache(sym_cache),
          err() {}

    WDbgArkAnalyzeWhiteList() = delete;

    void AddRangeWhiteList(const unsigned __int64 start, const unsigned __int64 end) {
        m_ranges.insert(std::make_pair(start, end));
    }
    void AddRangeWhiteList(const unsigned __int64 start, const unsigned __int32 size) {
        AddRangeWhiteList(start, start + size);
    }
    void RemoveAll() { m_ranges.clear(); }

    bool AddRangeWhiteList(const std::string &module_name);
    bool AddSymbolWhiteList(const std::string &symbol_name, const unsigned __int32 size);
    bool IsAddressInWhiteList(const unsigned __int64 address) const;

 private:
    Ranges m_ranges;
    std::shared_ptr<WDbgArkSymCache> m_sym_cache;
    std::stringstream err;
};
//////////////////////////////////////////////////////////////////////////
// analyze, display, print
//////////////////////////////////////////////////////////////////////////
class WDbgArkBPProxy {
 public:
     WDbgArkBPProxy() : m_bprinter_out(),
                        m_tp(new bprinter::TablePrinter(&m_bprinter_out)) {}
     virtual ~WDbgArkBPProxy() {}

     virtual void PrintHeader(void) { m_tp->PrintHeader(); }
     virtual void PrintFooter(void) { m_tp->PrintFooter(); }
     virtual void AddColumn(const std::string &header_name, const int column_width) {
         m_tp->AddColumn(header_name, column_width);
     }
     virtual void FlushOut(void) { m_tp->flush_out(); }
     virtual void FlushWarn(void) { m_tp->flush_warn(); }
     virtual void FlushErr(void) { m_tp->flush_err(); }

     template<typename T> WDbgArkBPProxy& operator<<(T input) {
         *m_tp << input;
         return *this;
     }

 protected:
     std::unique_ptr<bprinter::TablePrinter> m_tp;

 private:
    std::stringstream m_bprinter_out;
};
//////////////////////////////////////////////////////////////////////////
class WDbgArkAnalyzeBase: public WDbgArkBPProxy, public WDbgArkAnalyzeWhiteList {
 public:
    enum class AnalyzeType {
        AnalyzeTypeDefault,
        AnalyzeTypeCallback,
        AnalyzeTypeObjType,
        AnalyzeTypeIDT,
        AnalyzeTypeGDT,
        AnalyzeTypeDriver
    };

    explicit WDbgArkAnalyzeBase(const std::shared_ptr<WDbgArkSymCache> &sym_cache)
        : WDbgArkAnalyzeWhiteList(sym_cache),
          m_sym_cache(sym_cache),
          m_obj_helper(new WDbgArkObjHelper(sym_cache)) {}
    virtual ~WDbgArkAnalyzeBase() {}

    template<typename T> WDbgArkAnalyzeBase& operator<<(T input) {
        *m_tp << input;
        return *this;
    }

    static std::unique_ptr<WDbgArkAnalyzeBase> Create(const std::shared_ptr<WDbgArkSymCache> &sym_cache,
                                                      const AnalyzeType type = AnalyzeType::AnalyzeTypeDefault);

    //////////////////////////////////////////////////////////////////////////
    // analyze routines
    //////////////////////////////////////////////////////////////////////////
    virtual bool IsSuspiciousAddress(const unsigned __int64 address) const;
    virtual void Analyze(const unsigned __int64 address, const std::string &type, const std::string &additional_info);
    virtual void Analyze(const ExtRemoteTyped&, const ExtRemoteTyped&) {
        std::stringstream err;
        err << wa::showminus << __FUNCTION__ << ": unimplemented" << endlerr;
    }
    virtual void Analyze(const ExtRemoteTyped&, const std::string&, const unsigned __int32, const std::string&) {
        std::stringstream err;
        err << wa::showminus << __FUNCTION__ << ": unimplemented" << endlerr;
    }
    virtual void Analyze(const ExtRemoteTyped&) {
        std::stringstream err;
        err << wa::showminus << __FUNCTION__ << ": unimplemented" << endlerr;
    }
    virtual void PrintObjectDmlCmd(const ExtRemoteTyped &object);

    WDbgArkAnalyzeBase(WDbgArkAnalyzeBase const&) = delete;
    WDbgArkAnalyzeBase& operator=(WDbgArkAnalyzeBase const&) = delete;

 protected:
    std::shared_ptr<WDbgArkSymCache> m_sym_cache;

 private:
     std::unique_ptr<WDbgArkObjHelper> m_obj_helper;
};
//////////////////////////////////////////////////////////////////////////
// Default analyzer
//////////////////////////////////////////////////////////////////////////
class WDbgArkAnalyzeDefault: public WDbgArkAnalyzeBase {
 public:
    explicit WDbgArkAnalyzeDefault(const std::shared_ptr<WDbgArkSymCache> &sym_cache);
    virtual ~WDbgArkAnalyzeDefault() {}
};
//////////////////////////////////////////////////////////////////////////
// Callback analyzer
//////////////////////////////////////////////////////////////////////////
class WDbgArkAnalyzeCallback: public WDbgArkAnalyzeBase {
 public:
    explicit WDbgArkAnalyzeCallback(const std::shared_ptr<WDbgArkSymCache> &sym_cache);
    virtual ~WDbgArkAnalyzeCallback() {}
};
//////////////////////////////////////////////////////////////////////////
// Object type analyzer
//////////////////////////////////////////////////////////////////////////
class WDbgArkAnalyzeObjType: public WDbgArkAnalyzeBase {
 public:
    explicit WDbgArkAnalyzeObjType(const std::shared_ptr<WDbgArkSymCache> &sym_cache);
    virtual ~WDbgArkAnalyzeObjType() {}

    virtual void Analyze(const ExtRemoteTyped &ex_type_info, const ExtRemoteTyped &object);

 private:
    std::stringstream err;
};
//////////////////////////////////////////////////////////////////////////
// IDT analyzer
//////////////////////////////////////////////////////////////////////////
class WDbgArkAnalyzeIDT: public WDbgArkAnalyzeBase {
 public:
    explicit WDbgArkAnalyzeIDT(const std::shared_ptr<WDbgArkSymCache> &sym_cache);
    virtual ~WDbgArkAnalyzeIDT() {}
};
//////////////////////////////////////////////////////////////////////////
// GDT analyzer
//////////////////////////////////////////////////////////////////////////
class WDbgArkAnalyzeGDT: public WDbgArkAnalyzeBase {
 public:
    explicit WDbgArkAnalyzeGDT(const std::shared_ptr<WDbgArkSymCache> &sym_cache);
    virtual ~WDbgArkAnalyzeGDT() {}

    virtual void Analyze(const ExtRemoteTyped &gdt_entry,
                         const std::string &cpu_idx,
                         const unsigned __int32 selector,
                         const std::string &additional_info);

 private:
    std::string GetGDTSelectorName(const unsigned __int32 selector) const;
    unsigned __int32 GetGDTType(const ExtRemoteTyped &gdt_entry);
    std::string GetGDTTypeName(const ExtRemoteTyped &gdt_entry);
    unsigned __int32 GetGDTLimit(const ExtRemoteTyped &gdt_entry);
    unsigned __int64 GetGDTBase(const ExtRemoteTyped &gdt_entry);
    bool IsGDTPageGranularity(const ExtRemoteTyped &gdt_entry);
    bool IsGDTFlagPresent(const ExtRemoteTyped &gdt_entry);
    bool IsGDTTypeSystem(const ExtRemoteTyped &gdt_entry);
    unsigned __int32 GetGDTDpl(const ExtRemoteTyped &gdt_entry);

 private:
    std::stringstream err;
};

//////////////////////////////////////////////////////////////////////////
// Driver analyzer
//////////////////////////////////////////////////////////////////////////
class WDbgArkAnalyzeDriver: public WDbgArkAnalyzeBase {
 public:
    explicit WDbgArkAnalyzeDriver(const std::shared_ptr<WDbgArkSymCache> &sym_cache);
    virtual ~WDbgArkAnalyzeDriver() {}

    virtual void Analyze(const ExtRemoteTyped &object);

 private:
    std::vector<std::string> m_major_table_name;
    std::vector<std::string> m_fast_io_table_name;
    std::stringstream        out;
    std::stringstream        warn;
    std::stringstream        err;
};
//////////////////////////////////////////////////////////////////////////
}   // namespace wa

#endif  // ANALYZE_HPP_
