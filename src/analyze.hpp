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
#include <map>
#include <tuple>

#include "manipulators.hpp"
#include "objhelper.hpp"
#include "symcache.hpp"

namespace wa {
//////////////////////////////////////////////////////////////////////////
// white list range
//////////////////////////////////////////////////////////////////////////
class WDbgArkAnalyzeWhiteList {
 public:
    using Range = std::pair<uint64_t, uint64_t>;                        // start, end
    using Ranges = std::set<Range>;
    using WhiteListEntry = std::vector<std::string>;
    using WhiteListEntries = std::map<std::string, WhiteListEntry>;     // some name : vector of module names

    explicit WDbgArkAnalyzeWhiteList(const std::shared_ptr<WDbgArkSymCache> &sym_cache) : m_ranges(),
                                                                                          m_temp_ranges(),
                                                                                          m_wl_entries(),
                                                                                          m_sym_cache(sym_cache),
                                                                                          err() {}

    WDbgArkAnalyzeWhiteList() = delete;
    virtual ~WDbgArkAnalyzeWhiteList() {}

    //////////////////////////////////////////////////////////////////////////
    // permanent list
    //////////////////////////////////////////////////////////////////////////
    void AddRangeWhiteList(const uint64_t start, const uint64_t end) {
        AddRangeWhiteListInternal(start, end, &m_ranges);
    }

    void AddRangeWhiteList(const uint64_t start, const uint32_t size) {
        AddRangeWhiteList(start, start + size);
    }

    bool AddRangeWhiteList(const std::string &module_name) {
        return AddRangeWhiteListInternal(module_name, &m_ranges);
    }

    bool AddSymbolWhiteList(const std::string &symbol_name, const uint32_t size) {
        return AddSymbolWhiteListInternal(symbol_name, size, &m_ranges);
    }

    //////////////////////////////////////////////////////////////////////////
    // temp list
    //////////////////////////////////////////////////////////////////////////
    void AddTempRangeWhiteList(const uint64_t start, const uint64_t end) {
        AddRangeWhiteListInternal(start, end, &m_temp_ranges);
    }

    void AddTempRangeWhiteList(const uint64_t start, const uint32_t size) {
        AddTempRangeWhiteList(start, start + size);
    }

    bool AddTempRangeWhiteList(const std::string &module_name) {
        return AddRangeWhiteListInternal(module_name, &m_temp_ranges);
    }

    bool AddTempSymbolWhiteList(const std::string &symbol_name, const uint32_t size) {
        return AddSymbolWhiteListInternal(symbol_name, size, &m_temp_ranges);
    }

    void SetWhiteListEntries(const WhiteListEntries &entries) {
        InvalidateWhiteListEntries();
        m_wl_entries = entries;
    }

    const WhiteListEntries& GetWhiteListEntries(void) const { return m_wl_entries; }

    void AddTempWhiteList(const std::string &name);

    //////////////////////////////////////////////////////////////////////////
    // invalidate lists
    //////////////////////////////////////////////////////////////////////////
    void InvalidateRanges(void) { m_ranges.clear(); }
    void InvalidateTempRanges(void) { m_temp_ranges.clear(); }
    void InvalidateWhiteListEntries(void) { m_wl_entries.clear(); }

    //////////////////////////////////////////////////////////////////////////
    // check
    //////////////////////////////////////////////////////////////////////////
    bool IsAddressInWhiteList(const uint64_t address) const;

 private:
    Ranges m_ranges;
    Ranges m_temp_ranges;
    WhiteListEntries m_wl_entries;
    std::shared_ptr<WDbgArkSymCache> m_sym_cache;
    std::stringstream err;

 private:
    void AddRangeWhiteListInternal(const uint64_t start, const uint64_t end, Ranges* ranges) {
        ranges->insert({ start, end });
    }

    bool AddRangeWhiteListInternal(const std::string &module_name, Ranges* ranges);
    bool AddSymbolWhiteListInternal(const std::string &symbol_name, const uint32_t size, Ranges* ranges);
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
    std::stringstream m_bprinter_out;
    std::unique_ptr<bprinter::TablePrinter> m_tp;
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
    virtual bool IsSuspiciousAddress(const uint64_t address) const;
    virtual void Analyze(const uint64_t address, const std::string &type, const std::string &additional_info);
    virtual void Analyze(const ExtRemoteTyped&, const ExtRemoteTyped&) {
        std::stringstream locerr;
        locerr << wa::showminus << __FUNCTION__ << ": unimplemented" << endlerr;
    }
    virtual void Analyze(const ExtRemoteTyped&, const std::string&, const uint32_t, const std::string&) {
        std::stringstream locerr;
        locerr << wa::showminus << __FUNCTION__ << ": unimplemented" << endlerr;
    }
    virtual void Analyze(const ExtRemoteTyped&) {
        std::stringstream locerr;
        locerr << wa::showminus << __FUNCTION__ << ": unimplemented" << endlerr;
    }
    virtual void PrintObjectDmlCmd(const ExtRemoteTyped &object);

    WDbgArkAnalyzeBase(WDbgArkAnalyzeBase const&) = delete;
    WDbgArkAnalyzeBase& operator=(WDbgArkAnalyzeBase const&) = delete;

 protected:
    std::shared_ptr<WDbgArkSymCache> m_sym_cache;
    std::unique_ptr<WDbgArkObjHelper> m_obj_helper;

 private:
    using ObjDmlCmd = std::tuple<std::string, std::string, std::string>;
    std::map<std::string, ObjDmlCmd> m_object_dml_cmd = {
        { "Type", std::make_tuple("<exec cmd=\"dx -r1 *(nt!_OBJECT_TYPE *)", "\">", "</exec>") },
        { "Directory", std::make_tuple("<exec cmd=\"dx -r1 *(nt!_OBJECT_DIRECTORY *)", "\">", "</exec>") },
        { "Process", std::make_tuple("<exec cmd=\"dx -r1 *(nt!_EPROCESS *)", "\">", "</exec>") },
        { "Thread", std::make_tuple("<exec cmd=\"dx -r1 *(nt!_ETHREAD *)", "\">", "</exec>") },
        { "Device", std::make_tuple("<exec cmd=\"dx -r1 *(nt!_DEVICE_OBJECT *)", "\">", "</exec>") },
        { "Driver", std::make_tuple("<exec cmd=\"dx -r1 *(nt!_DRIVER_OBJECT *)", "\">", "</exec>") },
        { "File", std::make_tuple("<exec cmd=\"dx -r1 *(nt!_FILE_OBJECT *)", "\">", "</exec>") },
        { "Section", std::make_tuple("<exec cmd=\"dx -r1 *(nt!_SECTION *)", "\">", "</exec>") },
        { "Key", std::make_tuple("<exec cmd=\"dx -r1 *(nt!_CM_KEY_BODY *)", "\">", "</exec>") }
    };
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
                         const uint32_t selector,
                         const std::string &additional_info);

 private:
    std::string GetGDTSelectorName(const uint32_t selector) const;
    uint32_t GetGDTType(const ExtRemoteTyped &gdt_entry);
    std::string GetGDTTypeName(const ExtRemoteTyped &gdt_entry);
    uint32_t GetGDTLimit(const ExtRemoteTyped &gdt_entry);
    uint64_t GetGDTBase(const ExtRemoteTyped &gdt_entry);
    bool IsGDTPageGranularity(const ExtRemoteTyped &gdt_entry);
    bool IsGDTFlagPresent(const ExtRemoteTyped &gdt_entry);
    bool IsGDTTypeSystem(const ExtRemoteTyped &gdt_entry);
    uint32_t GetGDTDpl(const ExtRemoteTyped &gdt_entry);

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
    void DisplayMajorTable(const ExtRemoteTyped &object);
    void DisplayFastIo(const ExtRemoteTyped &object);
    void DisplayFsFilterCallbacks(const ExtRemoteTyped &object);

 private:
    std::stringstream out;
    std::stringstream warn;
    std::stringstream err;
};
//////////////////////////////////////////////////////////////////////////
}   // namespace wa

#endif  // ANALYZE_HPP_
