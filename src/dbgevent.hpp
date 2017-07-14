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

#if _MSC_VER > 1000
#pragma once
#endif

#ifndef SRC_DBG_EVENT_HPP_
#define SRC_DBG_EVENT_HPP_

#include <engextcpp.hpp>

#include <cstdint>
#include <atomic>

#include "bp.hpp"

namespace wa {
//////////////////////////////////////////////////////////////////////////
// debug events helper base class
//////////////////////////////////////////////////////////////////////////
class WDbgArkDbgEventsBase : public IDebugEventCallbacks {
 public:
    WDbgArkDbgEventsBase() : m_ref(1) {}
    virtual ~WDbgArkDbgEventsBase() {}

    // IUnknown
    STDMETHOD_(ULONG, AddRef)();
    STDMETHOD_(ULONG, Release)();
    STDMETHOD(QueryInterface)(__in REFIID InterfaceId, __out PVOID* Interface);
#pragma warning(push)
#pragma warning(disable: 4100)
    // IDebugEventCallbacks
    STDMETHOD(ExitThread)(__in ULONG ExitCode) { return S_OK; }
    STDMETHOD(SessionStatus)(__in ULONG Status) { return S_OK; }
    STDMETHOD(ExitProcess)(__in ULONG ExitCode) { return S_OK; }
    STDMETHOD(GetInterestMask)(__out PULONG Mask) { return S_FALSE; }
    STDMETHOD(Breakpoint)(__in PDEBUG_BREAKPOINT Bp) { return S_OK; }
    STDMETHOD(SystemError)(__in ULONG Error, __in ULONG Level) { return S_OK; }
    STDMETHOD(ChangeEngineState)(__in ULONG Flags, __in ULONG64 Argument) { return S_OK; }
    STDMETHOD(ChangeSymbolState)(__in ULONG Flags, __in ULONG64 Argument) { return S_OK; }
    STDMETHOD(ChangeDebuggeeState)(__in ULONG Flags, __in ULONG64 Argument) { return S_OK; }
    STDMETHOD(UnloadModule)(__in_opt PCSTR ImageBaseName, __in ULONG64 BaseOffset) { return S_OK; }
    STDMETHOD(Exception)(__in PEXCEPTION_RECORD64 Exception, __in ULONG FirstChance) { return S_OK; }
    STDMETHOD(CreateThread)(__in ULONG64 Handle, __in ULONG64 DataOffset, __in ULONG64 StartOffset) { return S_OK; }
    STDMETHOD(LoadModule)(__in ULONG64 ImageFileHandle,
                          __in ULONG64 BaseOffset,
                          __in ULONG ModuleSize,
                          __in_opt PCSTR ModuleName,
                          __in_opt PCSTR ImageName,
                          __in ULONG CheckSum,
                          __in ULONG TimeDateStamp) { return S_OK; }
    STDMETHOD(CreateProcess)(__in ULONG64 ImageFileHandle,
                             __in ULONG64 Handle,
                             __in ULONG64 BaseOffset,
                             __in ULONG  ModuleSize,
                             __in_opt PCSTR ModuleName,
                             __in_opt  PCSTR ImageName,
                             __in ULONG CheckSum,
                             __in ULONG TimeDateStamp,
                             __in ULONG64 InitialThreadHandle,
                             __in ULONG64 ThreadDataOffset,
                             __in ULONG64 StartOffset) { return S_OK; }
#pragma warning(pop)

 private:
    std::atomic<uint32_t> m_ref;
};
//////////////////////////////////////////////////////////////////////////
// TODO(swwwolf): someday create an interface to register multiple BP callbacks for different purposes
class WDbgArkDbgEventsBP : public WDbgArkDbgEventsBase, public WDbgArkBP {
 public:
    explicit WDbgArkDbgEventsBP(const std::shared_ptr<WDbgArkSymCache> &sym_cache);
    WDbgArkDbgEventsBP() = delete;
    virtual ~WDbgArkDbgEventsBP() {}

    bool IsInited() const { return m_inited; }

    STDMETHOD(GetInterestMask)(__out PULONG Mask);
    STDMETHOD(Breakpoint)(__in PDEBUG_BREAKPOINT Bp);

 private:
    bool m_inited = false;
    std::stringstream err{};
    std::stringstream warn{};
    std::stringstream out{};
};

}   // namespace wa

#endif  // SRC_DBG_EVENT_HPP_
