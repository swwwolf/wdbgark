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
#include "symbols.hpp"
#include "process.hpp"
#include "wdrce.hpp"
#include "ver.hpp"

namespace wa {
//////////////////////////////////////////////////////////////////////////
// main class
//////////////////////////////////////////////////////////////////////////
class WDbgArk : public ExtExtension {
 public:
    //////////////////////////////////////////////////////////////////////////
    using IDebugSymbols3Ptr = _com_ptr_t<_com_IIID<IDebugSymbols3, &__uuidof(IDebugSymbols3)>>;

    using RemoteTypedCallback = std::function<HRESULT(WDbgArk* wdbg_ark_class,
                                                      const ExtRemoteTyped &object,
                                                      void* context)>;
    using RemoteDataCallback = std::function<HRESULT(WDbgArk* wdbg_ark_class,
                                                     const ExtRemoteData &object,
                                                     void* context)>;
    using ScanRoutine = std::function<void(void)>;
    using ScanCommand = std::pair<std::string, ScanRoutine>;
    using ScanCommands = std::vector<ScanCommand>;
    //////////////////////////////////////////////////////////////////////////
    WDbgArk();

    HRESULT __thiscall Initialize() {
        m_ExtMajorVersion = VER_MAJOR;
        m_ExtMinorVersion = VER_MINOR;

        return S_OK;
    }

    // this one is called _before_ main class destructor, but ExtExtension class is already dead
    // so, don't output any errors in these routines, don't call g_Ext->m_Something and so on
    void __thiscall Uninitialize() {
        if ( m_symbols3 != nullptr ) {
            m_dummy_pdb->RemoveDummyPdbModule(m_symbols3);  // unload dummypdb fake module
            RemoveSyntheticSymbols();                       // remove our symbols
        }
    }

    //////////////////////////////////////////////////////////////////////////
    // Main commands
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
    EXT_COMMAND_METHOD(wa_w32psdtflt);
    EXT_COMMAND_METHOD(wa_lxsdt);
    EXT_COMMAND_METHOD(wa_checkmsr);
    EXT_COMMAND_METHOD(wa_idt);
    EXT_COMMAND_METHOD(wa_gdt);
    EXT_COMMAND_METHOD(wa_colorize);
    EXT_COMMAND_METHOD(wa_crashdmpcall);
    EXT_COMMAND_METHOD(wa_haltables);
    EXT_COMMAND_METHOD(wa_drvmajor);
    EXT_COMMAND_METHOD(wa_ciinfo);
    EXT_COMMAND_METHOD(wa_cicallbacks);
    EXT_COMMAND_METHOD(wa_chknirvana);
    EXT_COMMAND_METHOD(wa_psppico);
    EXT_COMMAND_METHOD(wa_systables);
    EXT_COMMAND_METHOD(wa_apiset);
    EXT_COMMAND_METHOD(wa_eop);
    EXT_COMMAND_METHOD(wa_process_anomaly);

    //////////////////////////////////////////////////////////////////////////
    // Windows Debugger Remote Code Execution commands
    //////////////////////////////////////////////////////////////////////////
    EXT_COMMAND_METHOD(wdrce_cpuid);
    EXT_COMMAND_METHOD(wdrce_copyfile);

    //////////////////////////////////////////////////////////////////////////
    // init
    //////////////////////////////////////////////////////////////////////////
    bool Init();
    bool IsInited() const { return m_inited; }
    bool IsLiveKernel() const {
        return ((m_DebuggeeClass == DEBUG_CLASS_KERNEL) && (m_DebuggeeQual == DEBUG_KERNEL_CONNECTION));
    }

    void RequireLiveKernelMode() const throw(...) {
        if ( !IsLiveKernel() ) { throw ExtStatusException(S_OK, "live kernel-mode only"); }
    }

    //////////////////////////////////////////////////////////////////////////
    // walk routines
    //////////////////////////////////////////////////////////////////////////
    void WalkExCallbackList(const std::string &list_count_name,
                            const uint64_t offset_list_count,
                            const uint32_t routine_count,
                            const std::string &list_head_name,
                            const uint64_t offset_list_head,
                            const uint32_t array_distance,
                            const std::string &type,
                            walkresType* output_list);

    void WalkAnyListWithOffsetToRoutine(const std::string &list_head_name,
                                        const uint64_t offset_list_head,
                                        const uint32_t link_offset,
                                        const bool is_double,
                                        const uint32_t offset_to_routine,
                                        const std::string &type,
                                        const std::string &ext_info,
                                        walkresType* output_list);

    void WalkAnyListWithOffsetToObjectPointer(const std::string &list_head_name,
                                              const uint64_t offset_list_head,
                                              const bool is_double,
                                              const uint32_t offset_to_object_pointer,
                                              void* context,
                                              RemoteDataCallback callback);

    void WalkDeviceNode(const uint64_t device_node_address,
                        void* context,
                        RemoteTypedCallback callback);

    void WalkShutdownList(const std::string &list_head_name, const std::string &type, walkresType* output_list);
    void WalkPnpLists(const std::string &type, walkresType* output_list);
    void WalkCallbackDirectory(const std::string &type, walkresType* output_list);

    void WalkPicoTable(const std::string &table_name, const uint32_t table_count);
    void WalkApiSetTable(const uint64_t header_offset, const std::shared_ptr<WDbgArkProcess> &process_helper);

    void AddSymbolPointer(const std::string &symbol_name,
                          const std::string &type,
                          const std::string &additional_info,
                          walkresType* output_list);

    void WalkDirectoryObject(const uint64_t directory_address,
                             void* context,
                             RemoteTypedCallback callback);

 private:
    //////////////////////////////////////////////////////////////////////////
    // callback routines
    //////////////////////////////////////////////////////////////////////////
    static HRESULT DirectoryObjectCallback(WDbgArk* wdbg_ark_class,
                                           const ExtRemoteTyped &object,
                                           void* context);

    static HRESULT ShutdownListCallback(WDbgArk* wdbg_ark_class,
                                        const ExtRemoteData &object_pointer,
                                        void* context);

    static HRESULT DirectoryObjectTypeCallback(WDbgArk* wdbg_ark_class,
                                               const ExtRemoteTyped &object,
                                               void* context);

    static HRESULT DirectoryObjectTypeCallbackListCallback(WDbgArk* wdbg_ark_class,
                                                           const ExtRemoteTyped &object,
                                                           void* context);

    static HRESULT DeviceNodeCallback(WDbgArk* wdbg_ark_class,
                                      const ExtRemoteTyped &device_node,
                                      void* context);
    //////////////////////////////////////////////////////////////////////////
    // helpers
    //////////////////////////////////////////////////////////////////////////
    void CallCorrespondingWalkListRoutine(const CallbacksInfo::const_iterator &citer,
                                          walkresType* output_list);
    //////////////////////////////////////////////////////////////////////////
    // private inits
    //////////////////////////////////////////////////////////////////////////
    void InitScanCommands();
    void InitCallbackCommands();
    //////////////////////////////////////////////////////////////////////////
    // synthetic symbols
    //////////////////////////////////////////////////////////////////////////
    void RemoveSyntheticSymbols();
    bool AddSyntheticSymbolAddressPtr(const uint64_t address, const std::string &name);
    bool FindDbgkLkmdCallbackArray();
    bool FindMiApiSetSchema();

 private:
    bool m_inited = false;
    bool m_is_cur_machine64 = false;
    ScanCommands m_scan_commands{};
    CallbacksInfo m_system_cb_commands{};
    std::vector<DEBUG_MODULE_AND_ID> m_synthetic_symbols{};
    std::shared_ptr<WDbgArkSymCache> m_sym_cache = std::make_shared<WDbgArkSymCache>();
    std::unique_ptr<WDbgArkObjHelper> m_obj_helper{ nullptr };
    std::unique_ptr<WDbgArkColorHack> m_color_hack{ nullptr };
    std::shared_ptr<WDbgArkDummyPdb> m_dummy_pdb{ nullptr };
    std::unique_ptr<WDbgArkSystemVer> m_system_ver{ nullptr };
    std::shared_ptr<WDbgArkSymbolsBase> m_symbols_base{ nullptr };
    std::unique_ptr<WDbgArkRce> m_wdrce{ nullptr };
    IDebugSymbols3Ptr m_symbols3{ nullptr };
};

}   // namespace wa

#endif  // WDBGARK_HPP_
