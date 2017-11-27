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

#ifndef DUMMYPDB_WDRCE_H_
#define DUMMYPDB_WDRCE_H_

#include "./init.h"

#define DEFAULT_BUFFER_CODE_SIZE    PAGE_SIZE

//////////////////////////////////////////////////////////////////////////
// Work items global data
//////////////////////////////////////////////////////////////////////////
typedef ULONG(__cdecl *DBGPRINTPROC)(_In_z_ _Printf_format_string_ PCSTR Format, ...);
typedef VOID(NTAPI *DBGBREAKPOINTWITHSTATUSPROC)(_In_ ULONG Status);
typedef VOID(NTAPI *RTLINITUNICODESTRINGPROC)(_Out_ PUNICODE_STRING DestinationString,
                                                  _In_opt_z_ __drv_aliasesMem PCWSTR SourceString);
typedef NTSTATUS(*IOCREATEFILEPROC)(_Out_ PHANDLE FileHandle,
                                    _In_ ACCESS_MASK DesiredAccess,
                                    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
                                    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
                                    _In_opt_ PLARGE_INTEGER AllocationSize,
                                    _In_ ULONG FileAttributes,
                                    _In_ ULONG ShareAccess,
                                    _In_ ULONG Disposition,
                                    _In_ ULONG CreateOptions,
                                    _In_opt_ PVOID EaBuffer,
                                    _In_ ULONG EaLength,
                                    _In_ CREATE_FILE_TYPE CreateFileType,
                                    _In_opt_ PVOID InternalParameters,
                                    _In_ ULONG Options);
typedef NTSTATUS(NTAPI *ZWCLOSEPROC)(_In_ HANDLE Handle);
typedef NTSTATUS(NTAPI *ZWQUERYINFORMATIONFILEPROC)(_In_ HANDLE FileHandle,
                                                    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
                                                    _Out_writes_bytes_(Length) PVOID FileInformation,
                                                    _In_ ULONG Length,
                                                    _In_ FILE_INFORMATION_CLASS FileInformationClass);
typedef PVOID(NTAPI *EXALLOCATEPOOLWITHTAGPROC)(_In_ __drv_strictTypeMatch(__drv_typeExpr) POOL_TYPE PoolType,
                                                _In_ SIZE_T NumberOfBytes,
                                                _In_ ULONG Tag);
typedef VOID(*EXFREEPOOLWITHTAGPROC)(_Pre_notnull_ __drv_freesMem(Mem) PVOID P, _In_ ULONG Tag);
typedef NTSTATUS(NTAPI *ZWCREATESECTIONPROC)(_Out_ PHANDLE SectionHandle,
                                             _In_ ACCESS_MASK DesiredAccess,
                                             _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
                                             _In_opt_ PLARGE_INTEGER MaximumSize,
                                             _In_ ULONG SectionPageProtection,
                                             _In_ ULONG AllocationAttributes,
                                             _In_opt_ HANDLE FileHandle);
typedef NTSTATUS(NTAPI *ZWMAPVIEWOFSECTIONPROC)(_In_ HANDLE SectionHandle,
                                                _In_ HANDLE ProcessHandle,
                                                _Outptr_result_bytebuffer_(*ViewSize) PVOID *BaseAddress,
                                                _In_ ULONG_PTR ZeroBits,
                                                _In_ SIZE_T CommitSize,
                                                _Inout_opt_ PLARGE_INTEGER SectionOffset,
                                                _Inout_ PSIZE_T ViewSize,
                                                _In_ SECTION_INHERIT InheritDisposition,
                                                _In_ ULONG AllocationType,
                                                _In_ ULONG Win32Protect);
typedef NTSTATUS(NTAPI *ZWUNMAPVIEWOFSECTIONPROC)(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress);
typedef void* (__cdecl *MEMSETPROC)(_Out_writes_bytes_all_(_Size) void* _Dst, _In_ int _Val, _In_ size_t _Size);
typedef void* (__cdecl *MEMCPYPROC)(_Out_writes_bytes_all_(_MaxCount) void* _Dst,
                                    _In_reads_bytes_(_MaxCount) const void *_Src,
                                    _In_ size_t _MaxCount);
typedef PMDL (*IOALLOCATEMDLPROC)(_In_opt_ __drv_aliasesMem PVOID VirtualAddress,
                                  _In_ ULONG Length,
                                  _In_ BOOLEAN SecondaryBuffer,
                                  _In_ BOOLEAN ChargeQuota,
                                  _Inout_opt_ PIRP Irp);
typedef VOID (*IOFREEMDLPROC)(PMDL Mdl);
typedef VOID (*MMBUILDMDLFORNONPAGEDPOOLPROC)(_Inout_ PMDL MemoryDescriptorList);
typedef NTSTATUS (*MMPROTECTMDLSYSTEMADDRESSPROC)(_In_ PMDL MemoryDescriptorList, _In_ ULONG NewProtect);
typedef PVOID(*MMMAPLOCKEDPAGESSPECIFYCACHEPROC)(_Inout_ PMDL MemoryDescriptorList,
                                                 _In_ __drv_strictType(KPROCESSOR_MODE / enum _MODE, __drv_typeConst)
                                                 KPROCESSOR_MODE AccessMode,
                                                 _In_ __drv_strictTypeMatch(__drv_typeCond) MEMORY_CACHING_TYPE CacheType,
                                                 _In_opt_ PVOID RequestedAddress,
                                                 _In_ ULONG BugCheckOnFailure,
                                                 _In_ ULONG Priority);
typedef VOID (*MMUNMAPLOCKEDPAGESPROC)(_In_ PVOID BaseAddress, _Inout_ PMDL MemoryDescriptorList);
//////////////////////////////////////////////////////////////////////////
typedef struct _WORKITEM_GLOBAL_DATA_IAT {
    DBGPRINTPROC fnt_DbgPrint;
    DBGBREAKPOINTWITHSTATUSPROC fnt_DbgBreakPointWithStatus;
    RTLINITUNICODESTRINGPROC fnt_RtlInitUnicodeString;
    IOCREATEFILEPROC fnt_IoCreateFile;
    ZWCLOSEPROC fnt_ZwClose;
    ZWQUERYINFORMATIONFILEPROC fnt_ZwQueryInformationFile;
    EXALLOCATEPOOLWITHTAGPROC fnt_ExAllocatePoolWithTag;
    EXFREEPOOLWITHTAGPROC fnt_ExFreePoolWithTag;
    IOALLOCATEMDLPROC fnt_IoAllocateMdl;
    IOFREEMDLPROC fnt_IoFreeMdl;
    MMBUILDMDLFORNONPAGEDPOOLPROC fnt_MmBuildMdlForNonPagedPool;
    MMPROTECTMDLSYSTEMADDRESSPROC fnt_MmProtectMdlSystemAddress;
    MMMAPLOCKEDPAGESSPECIFYCACHEPROC fnt_MmMapLockedPagesSpecifyCache;
    MMUNMAPLOCKEDPAGESPROC fnt_MmUnmapLockedPages;
    ZWCREATESECTIONPROC fnt_ZwCreateSection;
    ZWMAPVIEWOFSECTIONPROC fnt_ZwMapViewOfSection;
    ZWUNMAPVIEWOFSECTIONPROC fnt_ZwUnmapViewOfSection;
    MEMSETPROC fnt_memset;
    MEMCPYPROC fnt_memcpy;
} WORKITEM_GLOBAL_DATA_IAT, *PWORKITEM_GLOBAL_DATA_IAT;
//////////////////////////////////////////////////////////////////////////
// CPUID as a work item
//////////////////////////////////////////////////////////////////////////
typedef struct _CPUID_WORKER_ENTRY {
    int function_id;
    int subfunction_id;
} CPUID_WORKER_ENTRY, *PCPUID_WORKER_ENTRY;
//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////
// Copy file as a work item
//////////////////////////////////////////////////////////////////////////
typedef struct _COPYFILE_WORKER_ENTRY {
    WCHAR file_path[1024];
} COPYFILE_WORKER_ENTRY, *PCOPYFILE_WORKER_ENTRY;
//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////
// Query directory as a work item
//////////////////////////////////////////////////////////////////////////
typedef struct _QUERYDIR_WORKER_ENTRY {
    WCHAR dir_path[1024];
} QUERYDIR_WORKER_ENTRY, *PQUERYDIR_WORKER_ENTRY;
//////////////////////////////////////////////////////////////////////////
// Function
//              "CpuidWorker"
// Output
//              "%s : EAX = 0x%X, EBX = 0x%X, ECX = 0x%X, EDX = 0x%X. Hit \'go\' to continue.\n"
// Function
//              "CopyfileWorker"
// Output
//              "%s : Buffer = 0x%p, Size = 0x%p. Hit \'go\' to continue and free the buffer.\n"
typedef struct _WORKITEM_GLOBAL_DATA_PRINT {
    CHAR Function[16];
    CHAR Output[112];
} WORKITEM_GLOBAL_DATA_PRINT, *PWORKITEM_GLOBAL_DATA_PRINT;
//////////////////////////////////////////////////////////////////////////
typedef struct _WORKITEM_GLOBAL_DATA {
    PWORK_QUEUE_ITEM ExpDebuggerWorkItem;           // pointer to the hooked work item
    WORK_QUEUE_ITEM ExpDebuggerWorkItemOriginal;    // copy of original bytes of the hooked work item
    __volatile PLONG ExpDebuggerWork;               // pointer to the FSM state variable
    PVOID BufferCode;                               // relocated buffer for code
    ULONG BufferCodeSize;                           // size of code buffer
    PVOID BufferData;                               // relocated buffer for data
    ULONG BufferDataSize;                           // size of data buffer
    WORKITEM_GLOBAL_DATA_IAT Iat;                   // import table
    WORKITEM_GLOBAL_DATA_PRINT Print;               // output parameters

    // all parameters should be here!
    union Parameters {
        CPUID_WORKER_ENTRY CpuidEntry;
        COPYFILE_WORKER_ENTRY CopyfileEntry;
        QUERYDIR_WORKER_ENTRY QuerydirEntry;
    } p;                                            // function parameters
} WORKITEM_GLOBAL_DATA, *PWORKITEM_GLOBAL_DATA;

static_assert(sizeof(WORKITEM_GLOBAL_DATA) <= 0x1000, "Invalid WORKITEM_GLOBAL_DATA size");
//////////////////////////////////////////////////////////////////////////
// This macros allocates code/data buffers to use by next command
#define WORKITEM_GLOBAL_RELOCATE_PROLOG(_x_) {                                                                  \
    PWORKITEM_GLOBAL_DATA Temp = (PWORKITEM_GLOBAL_DATA)(_x_);                                                  \
    if ( !ARGUMENT_PRESENT(Temp->BufferCode) ) {                                                                \
        PMDL Mdl = Temp->Iat.fnt_IoAllocateMdl(Temp, sizeof(*Temp), FALSE, FALSE, NULL);                        \
        if ( ARGUMENT_PRESENT(Mdl) ) {                                                                          \
            Temp->Iat.fnt_MmBuildMdlForNonPagedPool(Mdl);                                                       \
            Temp = (PWORKITEM_GLOBAL_DATA)Temp->Iat.fnt_MmMapLockedPagesSpecifyCache(Mdl,                       \
                                                                                     KernelMode,                \
                                                                                     MmCached,                  \
                                                                                     NULL,                      \
                                                                                     FALSE,                     \
                                                                                     NormalPagePriority);       \
            if ( ARGUMENT_PRESENT(Temp) ) {                                                                     \
                if ( NT_SUCCESS(Temp->Iat.fnt_MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE)) ) {               \
                    Temp->BufferCode = Temp->Iat.fnt_ExAllocatePoolWithTag(NonPagedPoolExecute,                 \
                                                                           DEFAULT_BUFFER_CODE_SIZE,            \
                                                                           POOL_TAG);                           \
                    if ( ARGUMENT_PRESENT(Temp->BufferCode) ) {                                                 \
                        Temp->BufferCodeSize = DEFAULT_BUFFER_CODE_SIZE;                                        \
                        if ( !ARGUMENT_PRESENT(Temp->BufferData) ) {                                            \
                            Temp->BufferData = Temp->Iat.fnt_ExAllocatePoolWithTag(NonPagedPool,                \
                                                                                   sizeof(*Temp),               \
                                                                                   POOL_TAG);                   \
                            if ( ARGUMENT_PRESENT(Temp->BufferData) ) {                                         \
                                Temp->BufferDataSize = sizeof(*Temp);                                           \
                            } else {                                                                            \
                                Temp->Iat.fnt_ExFreePoolWithTag(Temp->BufferCode, POOL_TAG);                    \
                                Temp->BufferCode = NULL;                                                        \
                                Temp->BufferCodeSize = 0;                                                       \
                            }                                                                                   \
                        }                                                                                       \
                    }                                                                                           \
                }                                                                                               \
                Temp->Iat.fnt_MmUnmapLockedPages(Temp, Mdl);                                                    \
            }                                                                                                   \
            Temp->Iat.fnt_IoFreeMdl(Mdl);                                                                       \
        }                                                                                                       \
    }                                                                                                           \
}
//////////////////////////////////////////////////////////////////////////
// It should be OK to just copy memory, because ExpDebuggerWork is still in a busy state (2), but
// don't touch _LIST_ENTRY
#define WORKITEM_GLOBAL_DATA_PROLOG(_x_) {                                                                      \
    (_x_)->Iat.fnt_memcpy(&((_x_)->ExpDebuggerWorkItem->WorkerRoutine),                                         \
                          &((_x_)->ExpDebuggerWorkItemOriginal.WorkerRoutine),                                  \
                          sizeof((_x_)->ExpDebuggerWorkItemOriginal) - RTL_FIELD_SIZE(WORK_QUEUE_ITEM, List));  \
    InterlockedExchange((_x_)->ExpDebuggerWork, 0L);                                                            \
    WORKITEM_GLOBAL_RELOCATE_PROLOG((_x_));                                                                     \
}
//////////////////////////////////////////////////////////////////////////
#endif  // DUMMYPDB_WDRCE_H_
