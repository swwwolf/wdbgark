/*
    * WinDBG Anti-RootKit extension
    * Copyright © 2013-2018  Vyacheslav Rusakoff
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
#include "whitelist.hpp"
#include "bproxy.hpp"
#include "symbols.hpp"
#include "process.hpp"
#include "processhlp.hpp"

namespace wa {
//////////////////////////////////////////////////////////////////////////
// DML commands class
//////////////////////////////////////////////////////////////////////////
class WDbgArkAnalyzeDmlCommand {
 public:
    explicit WDbgArkAnalyzeDmlCommand(const std::shared_ptr<WDbgArkSymCache> &sym_cache)
        : m_obj_helper(std::make_unique<WDbgArkObjHelper>(sym_cache)) {
        char buffer[MAX_PATH] = { 0 };

        if ( GetCurrentDirectory(MAX_PATH, &buffer[0]) && GetShortPathName(&buffer[0], &buffer[0], MAX_PATH) ) {
            m_current_directory = buffer;
            m_current_directory += R"(\)";
        }
    }

    virtual ~WDbgArkAnalyzeDmlCommand() = default;

    virtual std::string GetObjectDmlCommand(const ExtRemoteTyped &object);
    virtual std::string GetModuleDmlCommand(const uint64_t address,
                                            const std::string &module_name,
                                            const WDbgArkSymbolsBase &symbols_base);
    virtual std::string GetTokenDmlCommand(const uint64_t offset);
    virtual std::string GetProcessDmlCommand(const uint64_t offset);
    virtual std::string GetProcessDmlInfoCommand(const uint64_t offset, const std::streamsize size);
    virtual std::string GetAddressDmlCommand(const uint64_t offset);
    virtual std::string GetGdtAddressDmlCommand(const uint64_t offset, const uint32_t selector);

 protected:
    using ObjDmlCmd = std::tuple<std::string, std::string, std::string>;

    std::unique_ptr<WDbgArkObjHelper> m_obj_helper{ nullptr };
    std::string m_current_directory{};

    std::map<std::string, ObjDmlCmd> m_object_dml_cmd = {
        { "Type", std::make_tuple(R"(<exec cmd="dtx nt!_OBJECT_TYPE )", R"(">)", "</exec>") },
        { "Directory", std::make_tuple(R"(<exec cmd="dtx nt!_OBJECT_DIRECTORY )", R"(">)", "</exec>") },
        { "Process", std::make_tuple(R"(<exec cmd="dtx nt!_EPROCESS )", R"(">)", "</exec>") },
        { "Thread", std::make_tuple(R"(<exec cmd="dtx nt!_ETHREAD )", R"(">)", "</exec>") },
        { "Device", std::make_tuple(R"(<exec cmd="dtx nt!_DEVICE_OBJECT )", R"(">)", "</exec>") },
        { "Driver", std::make_tuple(R"(<exec cmd="dtx nt!_DRIVER_OBJECT )", R"(">)", "</exec>") },
        { "File", std::make_tuple(R"(<exec cmd="dtx nt!_FILE_OBJECT )", R"(">)", "</exec>") },
        { "Section", std::make_tuple(R"(<exec cmd="dtx nt!_SECTION )", R"(">)", "</exec>") },
        { "Key", std::make_tuple(R"(<exec cmd="dtx nt!_CM_KEY_BODY )", R"(">)", "</exec>") }
    };
};
//////////////////////////////////////////////////////////////////////////
// analyze, display, print
//////////////////////////////////////////////////////////////////////////
class WDbgArkAnalyzeBase: public WDbgArkBPProxy<char>, public WDbgArkAnalyzeWhiteList, public WDbgArkAnalyzeDmlCommand {
 public:
    enum class AnalyzeType {
        AnalyzeTypeDefault,
        AnalyzeTypeSDT,
        AnalyzeTypeCallback,
        AnalyzeTypeObjType,
        AnalyzeTypeIDT,
        AnalyzeTypeGDT,
        AnalyzeTypeDriver,
        AnalyzeTypeProcessToken,
        AnalyzeTypeProcessAnomaly
    };

    explicit WDbgArkAnalyzeBase(const std::shared_ptr<WDbgArkSymCache> &sym_cache)
        : WDbgArkAnalyzeWhiteList(sym_cache),
          WDbgArkAnalyzeDmlCommand(sym_cache),
          m_sym_cache(sym_cache) {}

    virtual ~WDbgArkAnalyzeBase() = default;

    WDbgArkAnalyzeBase(WDbgArkAnalyzeBase const&) = delete;
    WDbgArkAnalyzeBase& operator=(WDbgArkAnalyzeBase const&) = delete;

    template<class T>
    WDbgArkAnalyzeBase& operator<<(T input) {
        *m_tp << input;
        return *this;
    }

    static std::unique_ptr<WDbgArkAnalyzeBase> Create(const std::shared_ptr<WDbgArkSymCache> &sym_cache,
                                                      const AnalyzeType type = AnalyzeType::AnalyzeTypeDefault);

    //////////////////////////////////////////////////////////////////////////
    // analyze routines
    //////////////////////////////////////////////////////////////////////////
    virtual bool IsSuspiciousAddress(const uint64_t address) const;

    virtual void Analyze(const uint64_t address, const std::string &type, const std::string &info);

    virtual void Analyze(const uint64_t, const std::string&) {
        err << wa::showminus << __FUNCTION__ << ": unimplemented" << endlerr;
    }

    virtual void Analyze(const ExtRemoteTyped&, const ExtRemoteTyped&) {
        err << wa::showminus << __FUNCTION__ << ": unimplemented" << endlerr;
    }

    virtual void Analyze(const ExtRemoteTyped&, const std::string&, const uint32_t, const std::string&) {
        err << wa::showminus << __FUNCTION__ << ": unimplemented" << endlerr;
    }

    virtual void Analyze(const ExtRemoteTyped&) {
        err << wa::showminus << __FUNCTION__ << ": unimplemented" << endlerr;
    }

    virtual void Analyze(const WDbgArkRemoteTypedProcess&) {
        err << wa::showminus << __FUNCTION__ << ": unimplemented" << endlerr;
    }

    virtual void PrintObjectDmlCmd(const ExtRemoteTyped &object);

 protected:
    std::shared_ptr<WDbgArkSymCache> m_sym_cache{ nullptr };
};
//////////////////////////////////////////////////////////////////////////
// Default analyzer
//////////////////////////////////////////////////////////////////////////
class WDbgArkAnalyzeDefault: public WDbgArkAnalyzeBase {
 public:
    explicit WDbgArkAnalyzeDefault(const std::shared_ptr<WDbgArkSymCache> &sym_cache);
    virtual ~WDbgArkAnalyzeDefault() = default;
};
//////////////////////////////////////////////////////////////////////////
// Service table analyzer
//////////////////////////////////////////////////////////////////////////
class WDbgArkAnalyzeSDT : public WDbgArkAnalyzeBase {
 public:
    explicit WDbgArkAnalyzeSDT(const std::shared_ptr<WDbgArkSymCache> &sym_cache);
    virtual ~WDbgArkAnalyzeSDT() = default;

    virtual void Analyze(const uint64_t address, const std::string &type);

 private:
    uint64_t index = 0ULL;
};
//////////////////////////////////////////////////////////////////////////
// Callback analyzer
//////////////////////////////////////////////////////////////////////////
class WDbgArkAnalyzeCallback: public WDbgArkAnalyzeBase {
 public:
    explicit WDbgArkAnalyzeCallback(const std::shared_ptr<WDbgArkSymCache> &sym_cache);
    virtual ~WDbgArkAnalyzeCallback() = default;
};
//////////////////////////////////////////////////////////////////////////
// Object type analyzer
//////////////////////////////////////////////////////////////////////////
class WDbgArkAnalyzeObjType: public WDbgArkAnalyzeBase {
 public:
    explicit WDbgArkAnalyzeObjType(const std::shared_ptr<WDbgArkSymCache> &sym_cache);
    virtual ~WDbgArkAnalyzeObjType() = default;

    virtual void Analyze(const ExtRemoteTyped &ex_type_info, const ExtRemoteTyped &object);
};
//////////////////////////////////////////////////////////////////////////
// IDT analyzer
//////////////////////////////////////////////////////////////////////////
class WDbgArkAnalyzeIDT: public WDbgArkAnalyzeBase {
 public:
    explicit WDbgArkAnalyzeIDT(const std::shared_ptr<WDbgArkSymCache> &sym_cache);
    virtual ~WDbgArkAnalyzeIDT() = default;
};
//////////////////////////////////////////////////////////////////////////
// GDT analyzer
//////////////////////////////////////////////////////////////////////////
class WDbgArkAnalyzeGDT: public WDbgArkAnalyzeBase {
 public:
    explicit WDbgArkAnalyzeGDT(const std::shared_ptr<WDbgArkSymCache> &sym_cache);
    virtual ~WDbgArkAnalyzeGDT() = default;

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
    std::vector<std::string> m_gdt_sys_x64 = {
        make_string(SEG_SYS_UPPER_8_BYTE),
        make_string(SEG_SYS_RESERVED_1),
        make_string(SEG_SYS_LDT),
        make_string(SEG_SYS_RESERVED_3),
        make_string(SEG_SYS_RESERVED_4),
        make_string(SEG_SYS_RESERVED_5),
        make_string(SEG_SYS_RESERVED_6),
        make_string(SEG_SYS_RESERVED_7),
        make_string(SEG_SYS_RESERVED_8),
        make_string(SEG_SYS_TSS64_AVL),
        make_string(SEG_SYS_RESERVED_10),
        make_string(SEG_SYS_TSS64_BUSY),
        make_string(SEG_SYS_CALLGATE_64),
        make_string(SEG_SYS_RESERVED_13),
        make_string(SEG_SYS_INT_GATE_64),
        make_string(SEG_SYS_TRAP_GATE_64)
    };
    std::vector<std::string> m_gdt_sys_x86 = {
        make_string(SEG_SYS_RESERVED_0),
        make_string(SEG_SYS_TSS16_AVL),
        make_string(SEG_SYS_LDT),
        make_string(SEG_SYS_TSS16_BUSY),
        make_string(SEG_SYS_CALLGATE_16),
        make_string(SEG_SYS_TASKGATE),
        make_string(SEG_SYS_INT_GATE_16),
        make_string(SEG_SYS_TRAP_GATE_16),
        make_string(SEG_SYS_RESERVED_8),
        make_string(SEG_SYS_TSS32_AVL),
        make_string(SEG_SYS_RESERVED_10),
        make_string(SEG_SYS_TSS32_BUSY),
        make_string(SEG_SYS_CALLGATE_32),
        make_string(SEG_SYS_RESERVED_13),
        make_string(SEG_SYS_INT_GATE_32),
        make_string(SEG_SYS_TRAP_GATE_32)
    };
    std::vector<std::string> m_gdt_code_data = {
        make_string(SEG_DATA_RD),
        make_string(SEG_DATA_RDA),
        make_string(SEG_DATA_RDWR),
        make_string(SEG_DATA_RDWRA),
        make_string(SEG_DATA_RDEXPD),
        make_string(SEG_DATA_RDEXPDA),
        make_string(SEG_DATA_RDWREXPD),
        make_string(SEG_DATA_RDWREXPDA),
        make_string(SEG_CODE_EX),
        make_string(SEG_CODE_EXA),
        make_string(SEG_CODE_EXRD),
        make_string(SEG_CODE_EXRDA),
        make_string(SEG_CODE_EXC),
        make_string(SEG_CODE_EXCA),
        make_string(SEG_CODE_EXRDC),
        make_string(SEG_CODE_EXRDCA)
    };
    std::map<uint32_t, std::string> m_gdt_selector_x64 = {
        { KGDT64_NULL, make_string(KGDT64_NULL) },
        { KGDT64_R0_CODE, make_string(KGDT64_R0_CODE) },
        { KGDT64_R0_DATA, make_string(KGDT64_R0_DATA) },
        { KGDT64_R3_CMCODE, make_string(KGDT64_R3_CMCODE) },
        { KGDT64_R3_DATA, make_string(KGDT64_R3_DATA) },
        { KGDT64_R3_CODE, make_string(KGDT64_R3_CODE) },
        { KGDT64_SYS_TSS, make_string(KGDT64_SYS_TSS) },
        { KGDT64_R3_CMTEB, make_string(KGDT64_R3_CMTEB) }
    };
    std::map<uint32_t, std::string> m_gdt_selector_x86 = {
        { KGDT_R0_CODE, make_string(KGDT_R0_CODE) },
        { KGDT_R0_DATA, make_string(KGDT_R0_DATA) },
        { KGDT_R3_CODE, make_string(KGDT_R3_CODE) },
        { KGDT_R3_DATA, make_string(KGDT_R3_DATA) },
        { KGDT_TSS, make_string(KGDT_TSS) },
        { KGDT_R0_PCR, make_string(KGDT_R0_PCR) },
        { KGDT_R3_TEB, make_string(KGDT_R3_TEB) },
        { KGDT_LDT, make_string(KGDT_LDT) },
        { KGDT_DF_TSS, make_string(KGDT_DF_TSS) },
        { KGDT_NMI_TSS, make_string(KGDT_NMI_TSS) },
        { KGDT_GDT_ALIAS, make_string(KGDT_GDT_ALIAS) },
        { KGDT_CDA16, make_string(KGDT_CDA16) },
        { KGDT_CODE16, make_string(KGDT_CODE16) },
        { KGDT_STACK16, make_string(KGDT_STACK16) }
    };
};
//////////////////////////////////////////////////////////////////////////
// Driver analyzer
//////////////////////////////////////////////////////////////////////////
class WDbgArkAnalyzeDriver: public WDbgArkAnalyzeBase {
 public:
    explicit WDbgArkAnalyzeDriver(const std::shared_ptr<WDbgArkSymCache> &sym_cache);
    virtual ~WDbgArkAnalyzeDriver() = default;

    virtual void Analyze(const ExtRemoteTyped &object);

 private:
    void DisplayMajorTable(const ExtRemoteTyped &object);
    void DisplayFastIo(const ExtRemoteTyped &object);
    void DisplayFsFilterCallbacks(const ExtRemoteTyped &object);
    void DisplayClassCallbacks(const ExtRemoteTyped &object);
};
//////////////////////////////////////////////////////////////////////////
// Process token analyzer
//////////////////////////////////////////////////////////////////////////
class WDbgArkAnalyzeProcessToken : public WDbgArkAnalyzeBase {
 public:
    explicit WDbgArkAnalyzeProcessToken(const std::shared_ptr<WDbgArkSymCache> &sym_cache);
    virtual ~WDbgArkAnalyzeProcessToken() = default;

    virtual void Analyze(const WDbgArkRemoteTypedProcess &process);

 private:
    bool IsPrinted(const WDbgArkRemoteTypedProcess &process);
    void CheckTokenStolen(const WDbgArkRemoteTypedProcess &process);
    void CheckTokenPrivileges(const WDbgArkRemoteTypedProcess &process);

 private:
    std::map<uint64_t, WDbgArkRemoteTypedProcess> m_token_process{};    // token : process
    std::set<uint64_t> m_printed{};                                     // printed process
    bool m_check_token_privileges = false;

    const std::string m_anomaly_type_token_stolen{ "Stolen token" };
    const std::string m_anomaly_type_token_privs{ "Suspicious privileges" };
};
//////////////////////////////////////////////////////////////////////////
// Process anomaly analyzer
//////////////////////////////////////////////////////////////////////////
class WDbgArkAnalyzeProcessAnomaly : public WDbgArkAnalyzeBase {
public:
    explicit WDbgArkAnalyzeProcessAnomaly(const std::shared_ptr<WDbgArkSymCache> &sym_cache);
    virtual ~WDbgArkAnalyzeProcessAnomaly() = default;

    virtual void Analyze(const WDbgArkRemoteTypedProcess &process);

private:
    virtual bool IsSuspiciousProcess(const WDbgArkRemoteTypedProcess &process, std::string* type);
    virtual bool CheckProcessDoppelgang(const WDbgArkRemoteTypedProcess &process);

 private:
    const std::string m_anomaly_type_process_doppel{ "Doppelganged" };
};

}   // namespace wa

#endif  // ANALYZE_HPP_
