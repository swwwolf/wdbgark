/*
    * WinDBG Anti-RootKit extension dummy PDB driver
    * Copyright © 2015-2017  Vyacheslav Rusakoff
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

#ifdef __cplusplus
extern "C" {
#endif
    DRIVER_INITIALIZE DriverEntry;

    WORKER_THREAD_ROUTINE CpuidWorker;
#ifdef __cplusplus
}
#endif

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

#if defined(_X86_)
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
//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////
// _WOW64_INFO
//////////////////////////////////////////////////////////////////////////
#if !defined(_X86_)
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
NTSTATUS DriverEntry(_In_ DRIVER_OBJECT* DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    return STATUS_SUCCESS;
}
//////////////////////////////////////////////////////////////////////////
VOID CpuidWorker(_In_ PVOID Parameter) {
    WORKITEM_GLOBAL_DATA_PROLOG(Parameter);

    PWORKITEM_GLOBAL_DATA Global = (PWORKITEM_GLOBAL_DATA)Parameter;

    int Info[4];
    RtlZeroMemory(Info, sizeof(Info));
    __cpuidex(Info, Global->p.CpuidEntry.function_id, Global->p.CpuidEntry.subfunction_id);

    Global->Iat.fnt_DbgPrint(Global->Print.Output, Global->Print.Function, Info[0], Info[1], Info[2], Info[3]);
    Global->Iat.fnt_DbgBreakPointWithStatus(DBG_STATUS_WORKER);
}
//////////////////////////////////////////////////////////////////////////
