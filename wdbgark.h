/*
    * WinDBG Anti-RootKit extension
    * Copyright © 2013-2014  Vyacheslav Rusakoff
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

#ifndef _WDBGARK_H_
#define _WDBGARK_H_

#include "ddk.h"
#include "sdt_w32p.h"

#include <string>
#include <map>
#include <sstream>
#include <iomanip>
#include <vector>

using namespace std;

#define EXT_CLASS WDbgArk
#include <engextcpp.hpp>

class WDbgArk : public ExtExtension
{
public:

    typedef struct SystemCbCommandTag
    {
        string        list_count_name;
        string        list_head_name;
        unsigned long offset_to_routine;
    } SystemCbCommand;

    typedef HRESULT (*pfn_object_directory_walk_callback_routine)(WDbgArk* wdbg_ark_class,
                                                                  ExtRemoteTyped &object,
                                                                  void* context);

    typedef HRESULT (*pfn_any_list_w_pobject_walk_callback_routine)(WDbgArk* wdbg_ark_class,
                                                                    ExtRemoteData &object_pointer,
                                                                    void* context);

    typedef HRESULT (*pfn_device_node_walk_callback_routine)(WDbgArk* wdbg_ark_class,
                                                             ExtRemoteTyped &device_node,
                                                             void* context);

    WDbgArk();
    EXT_COMMAND_METHOD( ver );
    EXT_COMMAND_METHOD( scan );
    EXT_COMMAND_METHOD( systemcb );
    EXT_COMMAND_METHOD( objtype );
    EXT_COMMAND_METHOD( objtypeidx );
    EXT_COMMAND_METHOD( callouts );
    EXT_COMMAND_METHOD( pnptable );
    EXT_COMMAND_METHOD( ssdt );
    EXT_COMMAND_METHOD( w32psdt );
    EXT_COMMAND_METHOD( checkmsr );
    EXT_COMMAND_METHOD( idt );

    void Init();

    bool IsInited()
    {
        return inited;
    }

    unsigned long GetMinorBuild()
    {
        return minor_build;
    };

    /* walking routines */
    void WalkExCallbackList(const string &list_count_name,
                            const string &list_head_name,
                            const string &type);

    void WalkAnyListWithOffsetToRoutine(const string &list_head_name,
                                        const unsigned __int64 offset_list_head,
                                        bool is_double,
                                        const unsigned long offset_to_routine,
                                        const string &type);

    void WalkAnyListWithOffsetToObjectPointer(const string &list_head_name,
                                              const unsigned __int64 offset_list_head,
                                              bool is_double,
                                              const unsigned long offset_to_object_pointer,
                                              void* context,
                                              pfn_any_list_w_pobject_walk_callback_routine callback);

    void WalkShutdownList(const string &list_head_name, const string &type);

    void WalkPnpLists(const string &type);

    void WalkCallbackDirectory(const string &type);   

    void Call—orrespondingWalkListRoutine(map <string, SystemCbCommand>::const_iterator &citer);

    void WalkDeviceNode(const unsigned __int64 device_node_address,
                        void* context,
                        pfn_device_node_walk_callback_routine callback);

    /* object manager routines */
    void WalkDirectoryObject(const unsigned __int64 directory_address,
                             void* context,
                             pfn_object_directory_walk_callback_routine callback);

    unsigned __int64 FindObjectByName(const string &object_name, const unsigned __int64 directory_address);

    HRESULT GetObjectHeader(const ExtRemoteTyped &object, ExtRemoteTyped &object_header);

    HRESULT GetObjectHeaderNameInfo(ExtRemoteTyped &object_header, ExtRemoteTyped &object_header_name_info);

    HRESULT GetObjectName(ExtRemoteTyped &object, string &object_name);

    unsigned __int64 __forceinline ExFastRefGetObject(unsigned __int64 FastRef)
    {
        if ( IsCurMachine32() )
            return FastRef & ~MAX_FAST_REFS_X86;
        else
            return FastRef & ~MAX_FAST_REFS_X64;
    }

    /* analyze routines */
    void AnalyzeAddressAsSymbolPointer(const string &symbol_name,
                                       const string &type,
                                       const string &additional_info);

    void AnalyzeAddressAsRoutine(const unsigned __int64 address,
                                 const string &type,
                                 const string &additional_info);

    void AnalyzeObjectTypeInfo(ExtRemoteTyped &type_info);

private:

    map <string, SystemCbCommand> system_cb_commands;
    vector<string>                callout_names;

    /* callback routines */
    static HRESULT DirectoryObjectCallback(WDbgArk* wdbg_ark_class,
                                           ExtRemoteTyped &object,
                                           void* context);

    static HRESULT ShutdownListCallback(WDbgArk* wdbg_ark_class,
                                        ExtRemoteData &object_pointer,
                                        void* context);

    static HRESULT DirectoryObjectTypeCallback(WDbgArk* wdbg_ark_class,
                                               ExtRemoteTyped &object,
                                               void* context);

    static HRESULT DeviceNodeCallback(WDbgArk* wdbg_ark_class,
                                      ExtRemoteTyped &device_node,
                                      void* context);

    /* helpers */
    HRESULT GetModuleNames(const unsigned __int64 address,
                           string &image_name,
                           string &module_name,
                           string &loaded_image_name);

    HRESULT GetNameByOffset(const unsigned __int64 address, string &name);

    unsigned long GetCmCallbackItemFunctionOffset();
    unsigned long GetPowerCallbackItemFunctionOffset();
    unsigned long GetPnpCallbackItemFunctionOffset();

    string get_service_table_routine_name_internal(unsigned long index,
                                                   unsigned long max_count,
                                                   char** service_table);

    string get_service_table_routine_name(ServiceTableType type, unsigned long index);

    /* string routines */
    HRESULT UnicodeStringStructToString(ExtRemoteTyped &unicode_string, string &output_string);

    wstring string_to_wstring(const string& str)
    {
        return wstring( str.begin(), str.end() );
    }

    string wstring_to_string(const wstring& wstr)
    {
        return string( wstr.begin(), wstr.end() );
    }

    /* variables */
    bool          inited;
    bool          is_cur_machine64;
    unsigned long platform_id;
    unsigned long major_build;
    unsigned long minor_build;
    unsigned long service_pack_number;

    /* output streams */
    stringstream  out;
    stringstream  warn;
    stringstream  err;
};

/* global stream manipulators */
inline ostream& endlout(ostream& arg)
{
    stringstream ss;

    arg << "\n";
    ss << arg.rdbuf();
    g_Ext->Dml( "%s", ss.str().c_str() );
    arg.flush();

    return arg;
}

inline ostream& endlwarn(ostream& arg)
{
    stringstream ss;

    arg << "\n";
    ss << arg.rdbuf();
    g_Ext->DmlWarn( "%s", ss.str().c_str() );
    arg.flush();

    return arg;
}

inline ostream& endlerr(ostream& arg)
{
    stringstream ss;

    arg << "\n";
    ss << arg.rdbuf();
    g_Ext->DmlErr( "%s", ss.str().c_str() );
    arg.flush();

    return arg;
}

#endif // _WDBGARK_H_