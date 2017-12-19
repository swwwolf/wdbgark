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
    ULONG PageSize;
    ULONG Wow64ExecuteFlags;
    ULONG Unknown;
    ULONG InstrumentationCallback;
} WOW64_INFO, *PWOW64_INFO;

static_assert(FIELD_OFFSET(_WOW64_INFO, InstrumentationCallback) == 0x0C, "Invalid InstrumentationCallback offset");
#endif  // !_X86_
//////////////////////////////////////////////////////////////////////////

// Apiset resolution typedefs
// http://lucasg.github.io/2017/10/15/Api-set-resolution/
// https://gist.github.com/lucasg/9aa464b95b4b7344cb0cddbdb4214b25
// http://www.geoffchappell.com/studies/windows/win32/apisetschema/index.htm

//////////////////////////////////////////////////////////////////////////
// Windows 7 & Windows 8
//////////////////////////////////////////////////////////////////////////
struct _API_SET_NAMESPACE_ENTRY_W7 {
    ULONG NameOffset;                       // offset from start of map to name of API Set
    ULONG NameLength;                       // size, in bytes, of name of API Set
    ULONG DataOffset;                       // offset from start of map to structure that lists the API Set's hosts
                                            // points to API_SET_VALUE_ARRAY_W7
} API_SET_NAMESPACE_ENTRY_W7, *PAPI_SET_NAMESPACE_ENTRY_W7;
//////////////////////////////////////////////////////////////////////////
struct _API_SET_NAMESPACE_ARRAY_W7 {
    ULONG Version;                          // v2 on Windows 7, v4 on Windows 8.1  and v6 on Windows 10
    ULONG Count;                            // number of API Sets described by array that follows
    _API_SET_NAMESPACE_ENTRY_W7 Array[1];   // array of namespace entries
} API_SET_NAMESPACE_ARRAY_W7, *PAPI_SET_NAMESPACE_ARRAY_W7;
//////////////////////////////////////////////////////////////////////////
struct _API_SET_VALUE_ENTRY_W7 {
    ULONG NameOffset;                       // offset from start of map to name of importing module, in Unicode
    ULONG NameLength;                       // size, in bytes, of name of importing module
    ULONG ValueOffset;                      // offset from start of map to name of host module, in Unicode
    ULONG ValueLength;                      // size, in bytes, of name of host module
} API_SET_VALUE_ENTRY_W7, *PAPI_SET_VALUE_ENTRY_W7;
//////////////////////////////////////////////////////////////////////////
struct _API_SET_VALUE_ARRAY_W7 {
    ULONG Count;                            // number of hosts described by array that follows
    _API_SET_VALUE_ENTRY_W7 Array[1];       // array of entries for hosts
} API_SET_VALUE_ARRAY_W7, *PAPI_SET_VALUE_ARRAY_W7;
//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////
// Windows 8.1
//////////////////////////////////////////////////////////////////////////
struct _API_SET_NAMESPACE_ENTRY_W81 {
    ULONG Flags;                            // 0x01 bit set in ApiSetSchema if API Set is sealed;
                                            // 0x02 bit observed to be clear for API- and set for EXT-
    ULONG NameOffset;                       // offset from start of map to name of API Set
    ULONG NameLength;                       // size, in bytes, of name of API Set
    ULONG AliasOffset;                      // ignored; observed to be same as NameOffset
    ULONG AliasLength;                      // ignored; observed to be NameLength less 8
    ULONG DataOffset;                       // offset from start of map to structure that lists the API Set's hosts
                                            // points to API_SET_VALUE_ARRAY_W81
} API_SET_NAMESPACE_ENTRY_W81, *PAPI_SET_NAMESPACE_ENTRY_W81;
//////////////////////////////////////////////////////////////////////////
struct _API_SET_NAMESPACE_ARRAY_W81 {
    ULONG Version;                          // v2 on Windows 7, v4 on Windows 8.1  and v6 on Windows 10
    ULONG Size;                             // size of map in bytes
    ULONG Flags;                            // 0x01 bit set in ApiSetSchema if base schema is "sealed";
                                            // 0x02 bit set in schema extension
    ULONG Count;                            // number of API Sets described by array that follows
    _API_SET_NAMESPACE_ENTRY_W81 Array[1];  // array of namespace entries
} API_SET_NAMESPACE_ARRAY_W81, *PAPI_SET_NAMESPACE_ARRAY_W81;
//////////////////////////////////////////////////////////////////////////
struct _API_SET_VALUE_ENTRY_W81 {
    ULONG Flags;                            // ignored; observed to be 0
    ULONG NameOffset;                       // offset from start of map to name of importing module, in Unicode
    ULONG NameLength;                       // size, in bytes, of name of importing module
    ULONG ValueOffset;                      // offset from start of map to name of host module, in Unicode
    ULONG ValueLength;                      // size, in bytes, of name of host module
} API_SET_VALUE_ENTRY_W81, *PAPI_SET_VALUE_ENTRY_W81;
//////////////////////////////////////////////////////////////////////////
struct _API_SET_VALUE_ARRAY_W81 {
    ULONG Flags;                            // ignored; observed to be 0
    ULONG Count;                            // number of hosts described by array that follows
    _API_SET_VALUE_ENTRY_W81 Array[1];      // array of entries for hosts
} API_SET_VALUE_ARRAY_W81, *PAPI_SET_VALUE_ARRAY_W81;
//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////
// Windows 10
//////////////////////////////////////////////////////////////////////////
struct _API_SET_NAMESPACE_W10 {
    ULONG Version;          // v2 on Windows 7, v4 on Windows 8.1  and v6 on Windows 10
    ULONG Size;             // apiset map size (usually the .apiset section virtual size)
    ULONG Flags;            // according to Geoff Chappell, tells if the map is sealed or not.
    ULONG Count;            // hash table entry count
    ULONG EntryOffset;      // offset to the api set entries values
    ULONG HashOffset;       // offset to the api set entries hash indexes
    ULONG HashFactor;       // multiplier to use when computing hash
} API_SET_NAMESPACE_W10, *PAPI_SET_NAMESPACE_W10;
//////////////////////////////////////////////////////////////////////////
struct _API_SET_HASH_ENTRY_W10 {
    ULONG Hash;
    ULONG Index;
} API_SET_HASH_ENTRY_W10, *PAPI_SET_HASH_ENTRY_W10;
//////////////////////////////////////////////////////////////////////////
struct _API_SET_NAMESPACE_ENTRY_W10 {
    ULONG Flags;            // sealed flag in bit 0
    ULONG NameOffset;       // offset to the ApiSet library name PWCHAR (e.g. "api-ms-win-core-job-l2-1-1")
    ULONG NameLength;       // ignored
    ULONG HashedLength;     // apiset library name length
    ULONG DataOffset;       // offset to the list of hosts library implement the apiset contract
                            // (points to API_SET_VALUE_ENTRY array)
    ULONG DataCount;        // number of hosts libraries
} API_SET_NAMESPACE_ENTRY_W10, *PAPI_SET_NAMESPACE_ENTRY_W10;
//////////////////////////////////////////////////////////////////////////
struct _API_SET_VALUE_ENTRY_W10 {
    ULONG Flags;            // sealed flag in bit 0
    ULONG NameOffset;       // offset to the ApiSet library name PWCHAR (e.g. "api-ms-win-core-job-l2-1-1")
    ULONG NameLength;       // apiset library name length
    ULONG ValueOffset;      // offset to the Host library name PWCHAR (e.g. "ucrtbase.dll")
    ULONG ValueLength;      // host library name length
} API_SET_VALUE_ENTRY_W10, *PAPI_SET_VALUE_ENTRY_W10;
//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////
// Undocumented nt!_SECTION before Windows 10
// based on Googling, REing and on _MMVAD_SHORT
//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////
// Windows XP
//////////////////////////////////////////////////////////////////////////
struct _MMADDRESS_NODE_WXP {
    ULONG_PTR StartingVpn;
    ULONG_PTR EndingVpn;
    _MMADDRESS_NODE_WXP* Parent;
    _MMADDRESS_NODE_WXP* LeftChild;
    _MMADDRESS_NODE_WXP* RightChild;
} MMADDRESS_NODE_WXP, *PMMADDRESS_NODE_WXP;

#if defined(_X86_)
    static_assert(sizeof(_MMADDRESS_NODE_WXP) == 0x14, "Invalid _MMADDRESS_NODE_WXP size");
#else   // _WIN64
    static_assert(sizeof(_MMADDRESS_NODE_WXP) == 0x28, "Invalid _MMADDRESS_NODE_WXP size");
#endif  // _X86_

struct _SECTION_WXP {
    _MMADDRESS_NODE_WXP Address;
    PVOID Segment;
    LARGE_INTEGER SizeOfSection;
    ULONG Flags;
    struct {
        ULONG InitialPageProtection : 12;
        ULONG SessionId : 20;
    };
} SECTION_WXP, *PSECTION_WXP;

#if defined(_X86_)
    static_assert(sizeof(_SECTION_WXP) == 0x28, "Invalid SECTION_WXP size");
    static_assert(FIELD_OFFSET(_SECTION_WXP, Segment) == 0x14, "Invalid Segment offset");
#else   // _WIN64
    static_assert(sizeof(_SECTION_WXP) == 0x40, "Invalid SECTION_WXP size");
    static_assert(FIELD_OFFSET(_SECTION_WXP, Segment) == 0x28, "Invalid Segment offset");
#endif  // _X86_

//////////////////////////////////////////////////////////////////////////
// Windows 2003, Windows Vista, Windows 7
//////////////////////////////////////////////////////////////////////////
struct _MMADDRESS_NODE_W2K3 {
    union {
        LONG_PTR Balance : 2;
        _MMADDRESS_NODE_W2K3* Parent;
    } u;
    _MMADDRESS_NODE_W2K3* LeftChild;
    _MMADDRESS_NODE_W2K3* RightChild;
    ULONG_PTR StartingVpn;
    ULONG_PTR EndingVpn;
} MMADDRESS_NODE_W2K3, *PMMADDRESS_NODE_W2K3;

#if defined(_X86_)
    static_assert(sizeof(_MMADDRESS_NODE_W2K3) == 0x14, "Invalid _MMADDRESS_NODE_W2K3 size");
#else   // _WIN64
    static_assert(sizeof(_MMADDRESS_NODE_W2K3) == 0x28, "Invalid _MMADDRESS_NODE_W2K3 size");
#endif  // _X86_

struct _SECTION_W2K3 {
    _MMADDRESS_NODE_W2K3 Address;
    PVOID Segment;
    LARGE_INTEGER SizeOfSection;
    ULONG Flags;
    struct {
        ULONG InitialPageProtection : 12;
        ULONG SessionId : 20;
    };
} SECTION_W2K3, *PSECTION_W2K3;

#if defined(_X86_)
    static_assert(sizeof(_SECTION_W2K3) == 0x28, "Invalid _SECTION_W2K3 size");
    static_assert(FIELD_OFFSET(_SECTION_W2K3, Segment) == 0x14, "Invalid Segment offset");
#else   // _WIN64
    static_assert(sizeof(_SECTION_W2K3) == 0x40, "Invalid _SECTION_W2K3 size");
    static_assert(FIELD_OFFSET(_SECTION_W2K3, Segment) == 0x28, "Invalid Segment offset");
#endif  // _X86_

//////////////////////////////////////////////////////////////////////////
// Windows 8
//////////////////////////////////////////////////////////////////////////
struct _SECTION_W8 {
    RTL_BALANCED_NODE SectionNode;
    ULONG StartingVpn;
    ULONG EndingVpn;
    PVOID Segment;
    LARGE_INTEGER SizeOfSection;
    ULONG Flags;
    struct {
        ULONG InitialPageProtection : 12;
        ULONG SessionId : 19;
        ULONG NoValidationNeeded : 1;
    };
} SECTION_W8, *PSECTION_W8;

#if defined(_X86_)
    static_assert(sizeof(_SECTION_W8) == 0x28, "Invalid _SECTION_W8 size");
    static_assert(FIELD_OFFSET(_SECTION_W8, Segment) == 0x14, "Invalid Segment offset");
#else   // _WIN64
    static_assert(sizeof(_SECTION_W8) == 0x38, "Invalid _SECTION_W8 size");
    static_assert(FIELD_OFFSET(_SECTION_W8, Segment) == 0x20, "Invalid Segment offset");
#endif  // _X86_

//////////////////////////////////////////////////////////////////////////
// Windows 8.1
//////////////////////////////////////////////////////////////////////////  
struct _SECTION_W81 {
    RTL_BALANCED_NODE SectionNode;
    ULONG_PTR StartingVpn;
    ULONG_PTR EndingVpn;
    PVOID Segment;
    UINT64 SizeOfSection;
    ULONG Flags;
    struct {
        ULONG InitialPageProtection : 12;
        ULONG SessionId : 19;
        ULONG NoValidationNeeded : 1;
    };
} SECTION_W81, *PSECTION_W81;

#if defined(_X86_)
    static_assert(sizeof(_SECTION_W81) == 0x28, "Invalid _SECTION_W81 size");
    static_assert(FIELD_OFFSET(_SECTION_W81, Segment) == 0x14, "Invalid Segment offset");
#else   // _WIN64
    static_assert(sizeof(_SECTION_W81) == 0x40, "Invalid _SECTION_W81 size");
    static_assert(FIELD_OFFSET(_SECTION_W81, Segment) == 0x28, "Invalid Segment offset");
#endif  // _X86_
