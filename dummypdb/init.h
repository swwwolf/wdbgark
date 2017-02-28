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

#ifndef DUMMYPDB_INIT_H_
#define DUMMYPDB_INIT_H_

#include <ntifs.h>

//////////////////////////////////////////////////////////////////////////
// CPUID as a work item
//////////////////////////////////////////////////////////////////////////
typedef struct _CPUID_WORKER_ENTRY {
    int function_id;
    int subfunction_id;
} CPUID_WORKER_ENTRY, *PCPUID_WORKER_ENTRY;
//////////////////////////////////////////////////////////////////////////
// Work items global data
//////////////////////////////////////////////////////////////////////////
typedef ULONG(__cdecl *DBGPRINTPROC)(_In_z_ _Printf_format_string_ PCSTR Format, ...);
typedef VOID(NTAPI *DBGBREAKPOINTWITHSTATUSPROC)(_In_ ULONG Status);
//////////////////////////////////////////////////////////////////////////
typedef struct _WORKITEM_GLOBAL_DATA_IAT {
    DBGPRINTPROC fnt_DbgPrint;
    DBGBREAKPOINTWITHSTATUSPROC fnt_DbgBreakPointWithStatus;
} WORKITEM_GLOBAL_DATA_IAT, *PWORKITEM_GLOBAL_DATA_IAT;
//////////////////////////////////////////////////////////////////////////
// Function
//              "CpuidWorker",
// Output
//              "%s : EAX = 0x%X, EBX = 0x%X, ECX = 0x%X, EDX = 0x%X\n",
typedef struct _WORKITEM_GLOBAL_DATA_PRINT {
    CHAR Function[32];
    CHAR Output[128];
} WORKITEM_GLOBAL_DATA_PRINT, *PWORKITEM_GLOBAL_DATA_PRINT;
//////////////////////////////////////////////////////////////////////////
typedef struct _WORKITEM_GLOBAL_DATA {
    PWORK_QUEUE_ITEM ExpDebuggerWorkItem;           // pointer to the hooked work item
    WORK_QUEUE_ITEM ExpDebuggerWorkItemOriginal;    // copy of original bytes of the hooked work item
    __volatile PLONG ExpDebuggerWork;               // pointer to the FSM state variable
    WORKITEM_GLOBAL_DATA_IAT Iat;                   // import table
    WORKITEM_GLOBAL_DATA_PRINT Print;               // output parameters

    union Parameters {
        CPUID_WORKER_ENTRY CpuidEntry;
    } p;                                            // function parameters
} WORKITEM_GLOBAL_DATA, *PWORKITEM_GLOBAL_DATA;
//////////////////////////////////////////////////////////////////////////
// it should be OK to just copy memory, because ExpDebuggerWork is still in a busy state (2)
// don't touch _LIST_ENTRY
#define WORKITEM_GLOBAL_DATA_PROLOG(_x_) {\
    RtlCopyMemory(&((PWORKITEM_GLOBAL_DATA)(_x_))->ExpDebuggerWorkItem->WorkerRoutine, \
                  &((PWORKITEM_GLOBAL_DATA)(_x_))->ExpDebuggerWorkItemOriginal.WorkerRoutine, \
                  sizeof(((PWORKITEM_GLOBAL_DATA)(_x_))->ExpDebuggerWorkItemOriginal) - \
                  RTL_FIELD_SIZE(WORK_QUEUE_ITEM, List)); \
    InterlockedExchange(((PWORKITEM_GLOBAL_DATA)(_x_))->ExpDebuggerWork, 0L); }
//////////////////////////////////////////////////////////////////////////
#endif  // DUMMYPDB_INIT_H_
