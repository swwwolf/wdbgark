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

//////////////////////////////////////////////////////////////////////////
//  Include this after "#define EXT_CLASS WDbgArk" only
//////////////////////////////////////////////////////////////////////////

#if _MSC_VER > 1000
#pragma once
#endif

#ifndef PROCESSHLP_HPP_
#define PROCESSHLP_HPP_

#include <engextcpp.hpp>

#include <string>
#include <memory>

#include "manipulators.hpp"
#include "strings.hpp"
#include "symcache.hpp"
#include "dummypdb.hpp"
#include "processimplicithlp.hpp"

namespace wa {

class WDbgArkRemoteTypedProcess : public WDbgArkImplicitProcess, public ExtRemoteTyped {
 public:
    WDbgArkRemoteTypedProcess(const std::shared_ptr<WDbgArkSymCache> &sym_cache)
        : WDbgArkImplicitProcess(),
          ExtRemoteTyped() {
        m_sym_cache = sym_cache;
    }

    explicit WDbgArkRemoteTypedProcess(const std::shared_ptr<WDbgArkSymCache> &sym_cache, PCSTR Expr)
        : WDbgArkImplicitProcess(),
          ExtRemoteTyped(Expr) {
        m_sym_cache = sym_cache;
        Init();
    }

    explicit WDbgArkRemoteTypedProcess(const std::shared_ptr<WDbgArkSymCache> &sym_cache,
                                       const DEBUG_TYPED_DATA* Typed)
        : WDbgArkImplicitProcess(),
          ExtRemoteTyped(Typed) {
        m_sym_cache = sym_cache;
        Init();
    }

    explicit WDbgArkRemoteTypedProcess(const std::shared_ptr<WDbgArkSymCache> &sym_cache,
                                       const ExtRemoteTyped &Typed)
        : WDbgArkImplicitProcess(),
          ExtRemoteTyped(Typed) {
        m_sym_cache = sym_cache;
        Init();
    }

    WDbgArkRemoteTypedProcess(const std::shared_ptr<WDbgArkSymCache> &sym_cache, PCSTR Expr, ULONG64 Offset)
        : WDbgArkImplicitProcess(),
          ExtRemoteTyped(Expr, Offset) {
        m_sym_cache = sym_cache;
        Init();
    }

    WDbgArkRemoteTypedProcess(const std::shared_ptr<WDbgArkSymCache> &sym_cache,
                              PCSTR Type,
                              ULONG64 Offset,
                              bool PtrTo,
                              PULONG64 CacheCookie = nullptr,
                              PCSTR LinkField = nullptr)
        : WDbgArkImplicitProcess(),
          ExtRemoteTyped(Type,
                         Offset,
                         PtrTo,
                         CacheCookie,
                         LinkField) {
        m_sym_cache = sym_cache;
        Init();
    }

    virtual ~WDbgArkRemoteTypedProcess() = default;

    virtual WDbgArkRemoteTypedProcess& operator=(const DEBUG_TYPED_DATA* Typed) {
        Copy(Typed);
        Init();
        return *this;
    }

    virtual WDbgArkRemoteTypedProcess& operator=(const ExtRemoteTyped& Typed) {
        Copy(Typed);
        Init();
        return *this;
    }

    HRESULT SetImplicitProcess() {
        return WDbgArkImplicitProcess::SetImplicitProcess(*this);
    }

    // provide dummy pdb shared pointer here if you wanna get instrumentation callback info
    void SetDummyPdb(const std::shared_ptr<WDbgArkDummyPdb> &dummy_pdb) { m_dummy_pdb = dummy_pdb; }

    bool GetProcessImageFileName(std::string* image_name) {
        auto img_name = Field("ImageFileName");

        char buffer[100] = { 0 };
        *image_name = img_name.GetString(buffer, static_cast<ULONG>(sizeof(buffer)), img_name.GetTypeSize());

        return true;
    }

    bool GetSeAuditProcessCreationInfoImagePath(std::wstring* image_path) {
        auto image_file_name = Field("SeAuditProcessCreationInfo").Field("ImageFileName");

        if ( !image_file_name.GetPtr() ) {
            return false;
        }

        auto name = image_file_name.Field("Name");
        const auto [result, path] = UnicodeStringStructToString(name);

        if ( SUCCEEDED(result) ) {
            *image_path = path;
            return true;
        }

        return false;
    }

    bool GetProcessImageFilePathByFileObject(std::wstring* image_path) {
        if ( HasField("ImageFilePointer") ) {
            auto img_fp = Field("ImageFilePointer");

            if ( !img_fp.GetPtr() ) {
                return false;
            }

            auto file_name = img_fp.Field("FileName");
            const auto [result, path] = UnicodeStringStructToString(file_name);

            if ( SUCCEEDED(result) ) {
                *image_path = path;
                return true;
            }
        } else {
            auto section = Field("SectionObject");
            auto offset = section.GetPtr();

            if ( !offset ) {
                return false;
            }

            const std::string sec_obj("nt!_SECTION_OBJECT");
            auto segment = ExtRemoteTyped(sec_obj.c_str(),
                                          offset,
                                          false,
                                          m_sym_cache->GetCookieCache(sec_obj),
                                          nullptr).Field("Segment");

            offset = segment.GetPtr();

            if ( !offset ) {
                return false;
            }

            const std::string segm("nt!_SEGMENT");
            auto fp = ExtRemoteTyped(segm.c_str(),
                                     offset,
                                     false,
                                     m_sym_cache->GetCookieCache(segm),
                                     nullptr).Field("ControlArea").Field("FilePointer");

            if ( !fp.GetPtr() ) {
                return false;
            }

            auto file_name = fp.Field("FileName");
            const auto [result, path] = UnicodeStringStructToString(file_name);

            if ( SUCCEEDED(result) ) {
                *image_path = path;
                return true;
            }
        }

        return false;
    }

    bool GetProcessImageFilePath(std::wstring* image_path) {
        auto result = GetSeAuditProcessCreationInfoImagePath(image_path);

        if ( !result ) {
            result = GetProcessImageFilePathByFileObject(image_path);
        }

        return result;
    }

    uint64_t GetDataOffset() const { return m_Offset; }

    bool IsWow64Process() {
        if ( g_Ext->IsCurMachine32() ) {
            return false;
        }

        return (Field(m_wow64_proc_field_name.c_str()).GetPtr() != 0ULL);
    }

    uint64_t GetWow64ProcessPeb32() {
        if ( m_new_wow64 ) {
            return Field(m_wow64_proc_field_name.c_str()).Field("Peb").GetPtr();
        } else {
            return Field(m_wow64_proc_field_name.c_str()).GetPtr();
        }
    }

    uint64_t GetWow64InfoPtr() {
        const auto wow64peb = GetWow64ProcessPeb32();

        if ( !wow64peb ) {
            return 0ULL;
        }

        return (wow64peb + m_sym_cache->GetTypeSize("nt!_PEB32"));
    }

    uint64_t GetWow64InstrumentationCallback() {
        if ( m_dummy_pdb == nullptr ) {
            err << wa::showminus << __FUNCTION__ << ": Invalid pointer" << endlerr;
            return 0ULL;
        }

        const auto offset = GetWow64InfoPtr();

        if ( !offset ) {
            return 0ULL;
        }

        // check that PEB32 is not paged out
        try {
            const std::string peb32("nt!_PEB32");
            ExtRemoteTyped(peb32.c_str(),
                           GetWow64ProcessPeb32(),
                           false,
                           m_sym_cache->GetCookieCache(peb32),
                           nullptr).Field("Ldr").GetUlong();
        } catch ( const ExtRemoteException& ) {
            return 0ULL;
        }

        const auto wow_info = m_dummy_pdb->GetShortName() + "!_WOW64_INFO";
        ExtRemoteTyped wow64info(wow_info.c_str(), offset, false, m_sym_cache->GetCookieCache(wow_info), nullptr);

        return static_cast<uint64_t>(wow64info.Field("InstrumentationCallback").GetUlong());
    }

    // 6000 - 9600 x64 only
    // 10240+ x86/x64 ()
    uint64_t GetInstrumentationCallback() {
        if ( g_Ext->IsCurMachine32() ) {
            // 10240+ x86 process only: _EPROCESS->InstrumentationCallback
            return Field("InstrumentationCallback").GetPtr();
        }

        if ( !IsWow64Process() ) {
            // native x64 process: _EPROCESS->_KPROCESS->InstrumentationCallback
            return Field("Pcb").Field("InstrumentationCallback").GetPtr();
        } else {
            // WOW64 process
            return GetWow64InstrumentationCallback();
        }
    }

    uint64_t GetProcessApiSetMap() {
        return Field("Peb").Field("ApiSetMap").GetPtr();
    }

 private:
    void Init() {
        if ( m_sym_cache->GetTypeSize("nt!_EWOW64PROCESS") != 0UL ) {
            m_new_wow64 = true;     // 10586+
        }

        if ( g_Ext->IsCurMachine64() ) {
            if ( HasField("WoW64Process") ) {
                m_wow64_proc_field_name = "WoW64Process";
            } else {
                m_wow64_proc_field_name = "Wow64Process";
            }
        }
    }

 private:
    bool m_new_wow64 = false;
    std::string m_wow64_proc_field_name{};
    std::shared_ptr<WDbgArkSymCache> m_sym_cache{ nullptr };
    std::shared_ptr<WDbgArkDummyPdb> m_dummy_pdb{ nullptr };
};

}   // namespace wa

#endif  // PROCESSHLP_HPP_
