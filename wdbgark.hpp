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

#if _MSC_VER > 1000
#pragma once
#endif

#ifndef _WDBGARK_HPP_
#define _WDBGARK_HPP_

#include <string>
#include <map>
#include <sstream>
#include <iomanip>
#include <vector>
using namespace std;

#undef EXT_CLASS
#define EXT_CLASS WDbgArk
#include <engextcpp.hpp>

#include "sdt_w32p.hpp"
#include "process.hpp"
#include "objhelper.hpp"
#include "analyze.hpp"

//////////////////////////////////////////////////////////////////////////
// string routines
//////////////////////////////////////////////////////////////////////////
wstring __forceinline string_to_wstring(const string& str)
{
    return wstring( str.begin(), str.end() );
}

string __forceinline wstring_to_string(const wstring& wstr)
{
    return string( wstr.begin(), wstr.end() );
}

HRESULT UnicodeStringStructToString(ExtRemoteTyped &unicode_string, string &output_string);

//////////////////////////////////////////////////////////////////////////
// main class
//////////////////////////////////////////////////////////////////////////
class WDbgArk : public ExtExtension
{
public:

    //////////////////////////////////////////////////////////////////////////
    // class typedefs
    //////////////////////////////////////////////////////////////////////////
    typedef struct SystemCbCommandTag
    {
        string        list_count_name;
        string        list_head_name;
        unsigned long offset_to_routine;
    } SystemCbCommand;

    //////////////////////////////////////////////////////////////////////////
    typedef struct OutputWalkInfoTag
    {
        unsigned __int64 routine_address;
        string           type;
        string           info;
        string           list_head_name;
    } OutputWalkInfo;

    typedef vector<OutputWalkInfo> walkresType;

    typedef struct WalkCallbackContextTag
    {
        string       type;
        string       list_head_name;
        walkresType* output_list_pointer;
    } WalkCallbackContext;
    //////////////////////////////////////////////////////////////////////////
    typedef HRESULT (*pfn_object_directory_walk_callback_routine)(WDbgArk* wdbg_ark_class,
                                                                  ExtRemoteTyped &object,
                                                                  void* context);

    typedef HRESULT (*pfn_any_list_w_pobject_walk_callback_routine)(WDbgArk* wdbg_ark_class,
                                                                    ExtRemoteData &object_pointer,
                                                                    void* context);

    typedef HRESULT (*pfn_device_node_walk_callback_routine)(WDbgArk* wdbg_ark_class,
                                                             ExtRemoteTyped &device_node,
                                                             void* context);

    //////////////////////////////////////////////////////////////////////////
    // main commands
    //////////////////////////////////////////////////////////////////////////
    WDbgArk() { m_inited = false; }

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

    //////////////////////////////////////////////////////////////////////////
    // init
    //////////////////////////////////////////////////////////////////////////
    bool Init(void);
    bool IsInited(void){ return m_inited == true; }
    bool IsLiveKernel(void){ return m_DebuggeeClass == DEBUG_KERNEL_CONNECTION; }

    void RequireLiveKernelMode(void)
    {
        if ( !IsLiveKernel() )
        {
            throw ExtStatusException( S_OK, "live kernel-mode only" );
        }
    }

    //////////////////////////////////////////////////////////////////////////
    // walk routines
    //////////////////////////////////////////////////////////////////////////
    void Call—orrespondingWalkListRoutine(map <string, SystemCbCommand>::const_iterator &citer,
                                          walkresType &output_list);

    void WalkExCallbackList(const string &list_count_name,
                            const string &list_head_name,
                            const string &type,
                            walkresType &output_list);

    void WalkAnyListWithOffsetToRoutine(const string &list_head_name,
                                        const unsigned __int64 offset_list_head,
                                        bool is_double,
                                        const unsigned long offset_to_routine,
                                        const string &type,
                                        walkresType &output_list);

    void WalkAnyListWithOffsetToObjectPointer(const string &list_head_name,
                                              const unsigned __int64 offset_list_head,
                                              bool is_double,
                                              const unsigned long offset_to_object_pointer,
                                              void* context,
                                              pfn_any_list_w_pobject_walk_callback_routine callback);

    void WalkDeviceNode(const unsigned __int64 device_node_address,
                        void* context,
                        pfn_device_node_walk_callback_routine callback);

    void WalkShutdownList(const string &list_head_name, const string &type, walkresType &output_list);
    void WalkPnpLists(const string &type, walkresType &output_list);
    void WalkCallbackDirectory(const string &type, walkresType &output_list);

    void AddSymbolPointer(const string &symbol_name,
                          const string &type,
                          const string &additional_info,
                          walkresType &output_list);

    void WalkDirectoryObject(const unsigned __int64 directory_address,
                             void* context,
                             pfn_object_directory_walk_callback_routine callback);

private:

    map <string, SystemCbCommand> system_cb_commands;
    vector<string>                callout_names;

    //////////////////////////////////////////////////////////////////////////
    // callback routines
    //////////////////////////////////////////////////////////////////////////
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

    //////////////////////////////////////////////////////////////////////////
    // helpers
    //////////////////////////////////////////////////////////////////////////
    unsigned long GetCmCallbackItemFunctionOffset();
    unsigned long GetPowerCallbackItemFunctionOffset();
    unsigned long GetPnpCallbackItemFunctionOffset();

    string get_service_table_routine_name_internal(unsigned long index,
                                                   unsigned long max_count,
                                                   char** service_table);

    string get_service_table_routine_name(ServiceTableType type, unsigned long index);  

    //////////////////////////////////////////////////////////////////////////
    // variables
    //////////////////////////////////////////////////////////////////////////
    bool             m_inited;
    bool             m_is_cur_machine64;
    unsigned long    m_platform_id;
    unsigned long    m_major_build;
    unsigned long    m_minor_build;
    unsigned long    m_service_pack_number;

    WDbgArkObjHelper m_obj_helper;

    //////////////////////////////////////////////////////////////////////////
    // output streams
    //////////////////////////////////////////////////////////////////////////
    stringstream out;
    stringstream warn;
    stringstream err;
};

#endif // _WDBGARK_HPP_