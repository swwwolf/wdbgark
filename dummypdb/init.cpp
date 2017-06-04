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

    WORKER_THREAD_ROUTINE FreememWorker;

    WORKER_THREAD_ROUTINE CpuidWorker;
    WORKER_THREAD_ROUTINE CopyfileWorker;
    WORKER_THREAD_ROUTINE QuerydirWorker;
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
VOID FreememWorker(_In_ PVOID Parameter) {
    PWORKITEM_GLOBAL_DATA Global = (PWORKITEM_GLOBAL_DATA)Parameter;
    WORKITEM_GLOBAL_DATA_PROLOG(Global);

#ifndef _X86_
    PVOID BufferCode = Global->BufferCode;
    Global->Iat.fnt_ExFreePoolWithTag(Global->BufferData, POOL_TAG);
    return Global->Iat.fnt_ExFreePoolWithTag(BufferCode, POOL_TAG);
#else
    __asm {
        pop     edi     //
        pop     esi     // epilogue
        pop     ebx     //
        mov     eax, [edi + 18h]
        push    POOL_TAG
        push    eax
        lea     eax, [edi + 44h]
        push    eax
        mov     eax, [edi + 20h]
        push    POOL_TAG
        push    eax
        lea     eax, [edi + 44h]
        push    eax
        retn
    }
#endif  // _X86_
}

//////////////////////////////////////////////////////////////////////////
VOID CpuidWorker(_In_ PVOID Parameter) {
    PWORKITEM_GLOBAL_DATA Global = (PWORKITEM_GLOBAL_DATA)Parameter;
    WORKITEM_GLOBAL_DATA_PROLOG(Global);

    int Info[4];
    Global->Iat.fnt_memset(Info, 0, sizeof(Info));
    __cpuidex(Info, Global->p.CpuidEntry.function_id, Global->p.CpuidEntry.subfunction_id);

    Global->Iat.fnt_DbgPrint(Global->Print.Output, Global->Print.Function, Info[0], Info[1], Info[2], Info[3]);
    Global->Iat.fnt_DbgBreakPointWithStatus(DBG_STATUS_WORKER);
}
//////////////////////////////////////////////////////////////////////////
VOID CopyfileWorker(_In_ PVOID Parameter) {
    PWORKITEM_GLOBAL_DATA Global = (PWORKITEM_GLOBAL_DATA)Parameter;
    WORKITEM_GLOBAL_DATA_PROLOG(Global);

    UNICODE_STRING file_path;
    Global->Iat.fnt_RtlInitUnicodeString(&file_path, Global->p.CopyfileEntry.file_path);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &file_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE file_handle = NULL;
    IO_STATUS_BLOCK iosb;
    Global->Iat.fnt_memset(&iosb, 0, sizeof(iosb));

    NTSTATUS status = Global->Iat.fnt_IoCreateFile(&file_handle,
                                                   SYNCHRONIZE | FILE_READ_ATTRIBUTES,
                                                   &oa,
                                                   &iosb,
                                                   NULL,
                                                   0,
                                                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                                   FILE_OPEN,
                                                   FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                                                   NULL,
                                                   0,
                                                   CreateFileTypeNone,
                                                   NULL,
                                                   IO_NO_PARAMETER_CHECKING);

    if ( !NT_SUCCESS(status) ) {
        Global->Iat.fnt_DbgBreakPointWithStatus(DBG_STATUS_WORKER);
        return;
    }

    FILE_STANDARD_INFORMATION info;
    Global->Iat.fnt_memset(&info, 0, sizeof(info));
    Global->Iat.fnt_memset(&iosb, 0, sizeof(iosb));

    status = Global->Iat.fnt_ZwQueryInformationFile(file_handle, &iosb, &info, sizeof(info), FileStandardInformation);

    if ( !NT_SUCCESS(status) ) {
        Global->Iat.fnt_ZwClose(file_handle);
        Global->Iat.fnt_DbgBreakPointWithStatus(DBG_STATUS_WORKER);
        return;
    }

    PVOID Buffer = Global->Iat.fnt_ExAllocatePoolWithTag(PagedPool, (SIZE_T)info.EndOfFile.QuadPart, POOL_TAG);

    if ( !Buffer ) {
        Global->Iat.fnt_ZwClose(file_handle);
        Global->Iat.fnt_DbgBreakPointWithStatus(DBG_STATUS_WORKER);
        return;
    }

    InitializeObjectAttributes(&oa, NULL, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE section_handle = NULL;
    status = Global->Iat.fnt_ZwCreateSection(&section_handle,
                                             SECTION_ALL_ACCESS,
                                             &oa,
                                             NULL,
                                             PAGE_READONLY,
                                             SEC_COMMIT,
                                             file_handle);

    if ( !NT_SUCCESS(status) ) {
        Global->Iat.fnt_ExFreePoolWithTag(Buffer, POOL_TAG);
        Global->Iat.fnt_ZwClose(file_handle);
        Global->Iat.fnt_DbgBreakPointWithStatus(DBG_STATUS_WORKER);
        return;
    }

    PVOID base = NULL;
    LARGE_INTEGER offset = { 0 };
    SIZE_T view_size = 0;

    status = Global->Iat.fnt_ZwMapViewOfSection(section_handle,
                                                NtCurrentProcess(),
                                                &base,
                                                0,
                                                (SIZE_T)info.EndOfFile.QuadPart,
                                                &offset,
                                                &view_size,
                                                ViewUnmap,
                                                0,
                                                PAGE_READONLY);

    if ( !NT_SUCCESS(status) ) {
        Global->Iat.fnt_ZwClose(section_handle);
        Global->Iat.fnt_ExFreePoolWithTag(Buffer, POOL_TAG);
        Global->Iat.fnt_ZwClose(file_handle);
        Global->Iat.fnt_DbgBreakPointWithStatus(DBG_STATUS_WORKER);
        return;
    }

    Global->Iat.fnt_memcpy(Buffer, base, (SIZE_T)info.EndOfFile.QuadPart);

    Global->Iat.fnt_ZwUnmapViewOfSection(NtCurrentProcess(), base);
    Global->Iat.fnt_ZwClose(section_handle);
    Global->Iat.fnt_ZwClose(file_handle);

    Global->Iat.fnt_DbgPrint(Global->Print.Output, Global->Print.Function, Buffer, info.EndOfFile.QuadPart);
    Global->Iat.fnt_DbgBreakPointWithStatus(DBG_STATUS_WORKER);

    Global->Iat.fnt_ExFreePoolWithTag(Buffer, POOL_TAG);
}
//////////////////////////////////////////////////////////////////////////
VOID QuerydirWorker(_In_ PVOID Parameter) {
    PWORKITEM_GLOBAL_DATA Global = (PWORKITEM_GLOBAL_DATA)Parameter;
    WORKITEM_GLOBAL_DATA_PROLOG(Global);

    UNICODE_STRING dir_path;
    Global->Iat.fnt_RtlInitUnicodeString(&dir_path, Global->p.QuerydirEntry.dir_path);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &dir_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE dir_handle = NULL;
    IO_STATUS_BLOCK iosb;
    Global->Iat.fnt_memset(&iosb, 0, sizeof(iosb));

    NTSTATUS status = Global->Iat.fnt_IoCreateFile(
        &dir_handle,
        FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &oa,
        &iosb,
        NULL,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT,
        NULL,
        0,
        CreateFileTypeNone,
        NULL,
        IO_NO_PARAMETER_CHECKING | IO_IGNORE_SHARE_ACCESS_CHECK);

    if ( !NT_SUCCESS(status) ) {
        Global->Iat.fnt_DbgBreakPointWithStatus(DBG_STATUS_WORKER);
        return;
    }

    FILE_ID_BOTH_DIR_INFORMATION temp_info;

    status = ZwQueryDirectoryFile(dir_handle,
                                  NULL,
                                  NULL,
                                  NULL,
                                  &iosb,
                                  &temp_info,
                                  sizeof(temp_info),
                                  FileIdBothDirectoryInformation,
                                  FALSE,
                                  NULL,
                                  TRUE);

    if ( !NT_SUCCESS(status) ) {
        Global->Iat.fnt_ZwClose(dir_handle);
        Global->Iat.fnt_DbgBreakPointWithStatus(DBG_STATUS_WORKER);
        return;
    }



    //Global->Iat.fnt_DbgPrint(Global->Print.Output, Global->Print.Function, Info[0], Info[1], Info[2], Info[3]);
    Global->Iat.fnt_DbgBreakPointWithStatus(DBG_STATUS_WORKER);
}
//////////////////////////////////////////////////////////////////////////
