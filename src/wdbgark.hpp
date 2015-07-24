/*
    * WinDBG Anti-RootKit extension
    * Copyright © 2013-2015  Vyacheslav Rusakoff
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

#ifndef WDBGARK_HPP_
#define WDBGARK_HPP_

#undef EXT_CLASS
#define EXT_CLASS wa::WDbgArk
#include <engextcpp.hpp>

#if defined(_DEBUG)
    #define _CRTDBG_MAP_ALLOC
    #include <stdlib.h>
    #include <crtdbg.h>
#endif  // _DEBUG

#include <string>
#include <sstream>
#include <map>
#include <vector>
#include <memory>
#include <utility>
#include <functional>

#include "objhelper.hpp"
#include "colorhack.hpp"
#include "dummypdb.hpp"
#include "systemver.hpp"
#include "typedefs.hpp"
#include "symcache.hpp"

#include "ver.hpp"

namespace wa {
//////////////////////////////////////////////////////////////////////////
// main class
//////////////////////////////////////////////////////////////////////////
class WDbgArk : public ExtExtension {
 public:
    //////////////////////////////////////////////////////////////////////////
    using RemoteTypedCallback = std::function<HRESULT(WDbgArk* wdbg_ark_class,
                                                      const ExtRemoteTyped &object,
                                                      void* context)>;

    using RemoteDataCallback = std::function<HRESULT(WDbgArk* wdbg_ark_class,
                                                     const ExtRemoteData &object,
                                                     void* context)>;
    //////////////////////////////////////////////////////////////////////////
    WDbgArk();

    HRESULT __thiscall Initialize(void) {
        m_ExtMajorVersion = VER_MAJOR;
        m_ExtMinorVersion = VER_MINOR;

        return S_OK;
    }

    // this one is called _before_ main class destructor, but ExtExtension class is already dead
    // so, don't output any errors in these routines, don't call g_Ext->m_Something and so on
    void __thiscall Uninitialize(void) {
        if ( m_symbols3_iface.IsSet() ) {
            m_dummy_pdb->RemoveDummyPdbModule(m_symbols3_iface);    // unload dummypdb fake module
            RemoveSyntheticSymbols();                               // remove our symbols
            EXT_RELEASE(m_symbols3_iface);
        }
    }

    //////////////////////////////////////////////////////////////////////////
    // main commands
    //////////////////////////////////////////////////////////////////////////
    EXT_COMMAND_METHOD(wa_ver);
    EXT_COMMAND_METHOD(wa_scan);
    EXT_COMMAND_METHOD(wa_systemcb);
    EXT_COMMAND_METHOD(wa_objtype);
    EXT_COMMAND_METHOD(wa_objtypeidx);
    EXT_COMMAND_METHOD(wa_objtypecb);
    EXT_COMMAND_METHOD(wa_callouts);
    EXT_COMMAND_METHOD(wa_pnptable);
    EXT_COMMAND_METHOD(wa_ssdt);
    EXT_COMMAND_METHOD(wa_w32psdt);
    EXT_COMMAND_METHOD(wa_checkmsr);
    EXT_COMMAND_METHOD(wa_idt);
    EXT_COMMAND_METHOD(wa_gdt);
    EXT_COMMAND_METHOD(wa_colorize);
    EXT_COMMAND_METHOD(wa_crashdmpcall);
    EXT_COMMAND_METHOD(wa_haltables);
    EXT_COMMAND_METHOD(wa_drvmajor);
    EXT_COMMAND_METHOD(wa_cicallbacks);

    //////////////////////////////////////////////////////////////////////////
    // init
    //////////////////////////////////////////////////////////////////////////
    bool Init(void);
    bool IsInited(void) const { return m_inited; }
    bool IsLiveKernel(void) const {
        return ((m_DebuggeeClass == DEBUG_CLASS_KERNEL) && (m_DebuggeeQual == DEBUG_KERNEL_CONNECTION));
    }

    void RequireLiveKernelMode(void) const throw(...) {
        if ( !IsLiveKernel() ) { throw ExtStatusException(S_OK, "live kernel-mode only"); }
    }

    //////////////////////////////////////////////////////////////////////////
    // walk routines
    //////////////////////////////////////////////////////////////////////////
    void WalkExCallbackList(const std::string &list_count_name,
                            const unsigned __int64 offset_list_count,
                            const unsigned __int32 routine_count,
                            const std::string &list_head_name,
                            const unsigned __int64 offset_list_head,
                            const unsigned __int32 array_distance,
                            const std::string &type,
                            walkresType* output_list);

    void WalkAnyListWithOffsetToRoutine(const std::string &list_head_name,
                                        const unsigned __int64 offset_list_head,
                                        const unsigned __int32 link_offset,
                                        const bool is_double,
                                        const unsigned __int32 offset_to_routine,
                                        const std::string &type,
                                        const std::string &ext_info,
                                        walkresType* output_list);

    void WalkAnyListWithOffsetToObjectPointer(const std::string &list_head_name,
                                              const unsigned __int64 offset_list_head,
                                              const bool is_double,
                                              const unsigned __int32 offset_to_object_pointer,
                                              void* context,
                                              RemoteDataCallback callback);

    void WalkDeviceNode(const unsigned __int64 device_node_address,
                        void* context,
                        RemoteTypedCallback callback);

    void WalkShutdownList(const std::string &list_head_name, const std::string &type, walkresType* output_list);
    void WalkPnpLists(const std::string &type, walkresType* output_list);
    void WalkCallbackDirectory(const std::string &type, walkresType* output_list);

    void WalkAnyTable(const unsigned __int64 table_start,
                      const unsigned __int32 offset_table_skip_start,
                      const unsigned __int32 table_count,
                      const std::string &type,
                      walkresType* output_list,
                      bool break_on_null = false,
                      bool collect_null = false);

    void AddSymbolPointer(const std::string &symbol_name,
                          const std::string &type,
                          const std::string &additional_info,
                          walkresType* output_list);

    void WalkDirectoryObject(const unsigned __int64 directory_address,
                             void* context,
                             RemoteTypedCallback callback);

 private:
    //////////////////////////////////////////////////////////////////////////
    // callback routines
    //////////////////////////////////////////////////////////////////////////
    static HRESULT DirectoryObjectCallback(WDbgArk* wdbg_ark_class,
                                           const ExtRemoteTyped &object,
                                           void* context);

    static HRESULT ShutdownListCallback(WDbgArk*,
                                        const ExtRemoteData &object_pointer,
                                        void* context);

    static HRESULT DirectoryObjectTypeCallback(WDbgArk*,
                                               const ExtRemoteTyped &object,
                                               void* context);

    static HRESULT DirectoryObjectTypeCallbackListCallback(WDbgArk* wdbg_ark_class,
                                                           const ExtRemoteTyped &object,
                                                           void* context);

    static HRESULT DeviceNodeCallback(WDbgArk* wdbg_ark_class,
                                      const ExtRemoteTyped &device_node,
                                      void* context);

    static HRESULT DirectoryObjectDriverCallback(WDbgArk* wdbg_ark_class,
                                                 const ExtRemoteTyped &object,
                                                 void* context);

    //////////////////////////////////////////////////////////////////////////
    // helpers
    //////////////////////////////////////////////////////////////////////////
    void CallCorrespondingWalkListRoutine(const callbacksInfo::const_iterator &citer,
                                          walkresType* output_list);
    //////////////////////////////////////////////////////////////////////////
    // private inits
    //////////////////////////////////////////////////////////////////////////
    bool FindDbgkLkmdCallbackArray();
    void InitCallbackCommands(void);
    void InitCalloutNames(void);
    void InitGDTSelectors(void);
    void InitHalTables(void);
    //////////////////////////////////////////////////////////////////////////
    void RemoveSyntheticSymbols(void);

 private:
    //////////////////////////////////////////////////////////////////////////
    // variables
    //////////////////////////////////////////////////////////////////////////
    bool                              m_inited;
    bool                              m_is_cur_machine64;
    callbacksInfo                     m_system_cb_commands;
    std::vector<std::string>          m_callout_names;
    std::vector<unsigned __int32>     m_gdt_selectors;
    haltblInfo                        m_hal_tbl_info;
    std::vector<DEBUG_MODULE_AND_ID>  m_synthetic_symbols;
    std::shared_ptr<WDbgArkSymCache>  m_sym_cache;
    std::unique_ptr<WDbgArkObjHelper> m_obj_helper;
    std::unique_ptr<WDbgArkColorHack> m_color_hack;
    std::unique_ptr<WDbgArkDummyPdb>  m_dummy_pdb;
    std::unique_ptr<WDbgArkSystemVer> m_system_ver;
    ExtCheckedPointer<IDebugSymbols3> m_symbols3_iface;
    //////////////////////////////////////////////////////////////////////////
    // output streams
    //////////////////////////////////////////////////////////////////////////
    std::stringstream out;
    std::stringstream warn;
    std::stringstream err;
};

}   // namespace wa

#endif  // WDBGARK_HPP_
