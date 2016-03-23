/*
    * WinDBG Anti-RootKit extension dummy PDB driver
    * Copyright © 2015  Vyacheslav Rusakoff
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

#include "./init.h"

//////////////////////////////////////////////////////////////////////////
// _OBJECT_CALLBACK_ENTRY_COMMON
//////////////////////////////////////////////////////////////////////////
struct _OBJECT_CALLBACK_ENTRY_COMMON {
    LIST_ENTRY                  CallbackList;
    OB_OPERATION                Operations;
    ULONG                       Active;
    PVOID                       Handle;
    POBJECT_TYPE                ObjectType;
    POB_PRE_OPERATION_CALLBACK  PreOperation;
    POB_POST_OPERATION_CALLBACK PostOperation;
} OBJECT_CALLBACK_ENTRY_COMMON, *POBJECT_CALLBACK_ENTRY_COMMON;

#ifdef _X86_
    static_assert(sizeof(_OBJECT_CALLBACK_ENTRY_COMMON) == 0x20, "Invalid OBJECT_CALLBACK_ENTRY_COMMON size");
    static_assert(FIELD_OFFSET(_OBJECT_CALLBACK_ENTRY_COMMON, CallbackList) == 0x00, "Invalid CallbackList offset");
    static_assert(FIELD_OFFSET(_OBJECT_CALLBACK_ENTRY_COMMON, PreOperation) == 0x18, "Invalid PreOperation offset");
    static_assert(FIELD_OFFSET(_OBJECT_CALLBACK_ENTRY_COMMON, PostOperation) == 0x1C, "Invalid PostOperation offset");
#else   // _WIN64
    static_assert(sizeof(_OBJECT_CALLBACK_ENTRY_COMMON) == 0x38, "Invalid OBJECT_CALLBACK_ENTRY_COMMON size");
    static_assert(FIELD_OFFSET(_OBJECT_CALLBACK_ENTRY_COMMON, CallbackList) == 0x00, "Invalid CallbackList offset");
    static_assert(FIELD_OFFSET(_OBJECT_CALLBACK_ENTRY_COMMON, PreOperation) == 0x28, "Invalid PreOperation offset");
    static_assert(FIELD_OFFSET(_OBJECT_CALLBACK_ENTRY_COMMON, PostOperation) == 0x30, "Invalid PostOperation offset");
#endif  // _X86_

#ifndef _X86_
//////////////////////////////////////////////////////////////////////////
// _WOW64_INFO
//////////////////////////////////////////////////////////////////////////
struct _WOW64_INFO {
    ULONG32 PageSize;
    ULONG32 Wow64ExecuteFlags;
    ULONG32 Unknown;
    ULONG32 InstrumentationCallback;
} WOW64_INFO, *PWOW64_INFO;

static_assert(FIELD_OFFSET(_WOW64_INFO, InstrumentationCallback) == 0x0C, "Invalid InstrumentationCallback offset");

#endif  // !_X86_

//////////////////////////////////////////////////////////////////////////
// DriverEntry
//////////////////////////////////////////////////////////////////////////
NTSTATUS NTAPI DriverEntry(IN PDRIVER_OBJECT driver, IN PUNICODE_STRING driverKeyName) {
    UNREFERENCED_PARAMETER(driver);
    UNREFERENCED_PARAMETER(driverKeyName);

    return STATUS_SUCCESS;
}
