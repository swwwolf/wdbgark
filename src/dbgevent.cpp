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

#include <engextcpp.hpp>

#include "dbgevent.hpp"
#include "bp.hpp"
#include "manipulators.hpp"

namespace wa {
//////////////////////////////////////////////////////////////////////////
STDMETHODIMP_(ULONG) WDbgArkDbgEventsBase::AddRef() {
    return ++m_ref;
}

STDMETHODIMP_(ULONG) WDbgArkDbgEventsBase::Release() {
    if ( --m_ref == 0 ) {
        delete this;
        return 0;
    }

    return m_ref;
}

STDMETHODIMP WDbgArkDbgEventsBase::QueryInterface(REFIID InterfaceId, PVOID* Interface) {
    *Interface = nullptr;

    if ( IsEqualIID(InterfaceId, __uuidof(IUnknown)) || IsEqualIID(InterfaceId, __uuidof(IDebugEventCallbacks)) ) {
        *Interface = reinterpret_cast<IDebugEventCallbacks*>(this);
        AddRef();
        return S_OK;
    } else {
        return E_NOINTERFACE;
    }
}
//////////////////////////////////////////////////////////////////////////
WDbgArkDbgEventsBP::WDbgArkDbgEventsBP(const std::shared_ptr<WDbgArkSymCache> &sym_cache) : WDbgArkDbgEventsBase(),
                                                                                            WDbgArkBP(sym_cache) {
    m_inited = WDbgArkBP::IsInited();
}

STDMETHODIMP WDbgArkDbgEventsBP::GetInterestMask(PULONG Mask) {
    *Mask = DEBUG_EVENT_BREAKPOINT;
    return S_OK;
}

STDMETHODIMP WDbgArkDbgEventsBP::Breakpoint(PDEBUG_BREAKPOINT Bp) {
    if ( IsKnownBp(Bp) ) {
        uint64_t offset = 0;
        Bp->GetOffset(&offset);

        out << wa::showplus << __FUNCTION__ << ": known breakpoint at ";
        out << std::hex << std::showbase << offset << endlout;
        return DEBUG_STATUS_BREAK;
    }

    err << wa::showminus << __FUNCTION__ << " : unknown breakpoint" << endlerr;
    return DEBUG_STATUS_GO;
}

//////////////////////////////////////////////////////////////////////////
}   // namespace wa
