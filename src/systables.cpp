/*
    * WinDBG Anti-RootKit extension
    * Copyright © 2013-2017  Vyacheslav Rusakoff
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

/*
    Output:

    tcpip!IoctlDispatchTable, http!UlIoctlTable, http!UxIoctlTable, srv!SrvSmbDispatchTable,
    srv!SrvTransaction2DispatchTable, srv!SrvNtTransactionDispatchTable, srv!SrvApiDispatchTable,
    storport!StorportExtensionTable
*/

#include <sstream>
#include <memory>
#include <string>
#include <vector>
#include <functional>

#include "wdbgark.hpp"
#include "analyze.hpp"
#include "manipulators.hpp"
#include "memtable.hpp"

namespace wa {

using IsSupportedSystemTable = std::function<bool(const std::shared_ptr<WDbgArkSymCache>&, const std::string&)>;
using GetCountSystemTable = std::function<uint32_t(void)>;

typedef struct SystemTableTag {
    std::string name;
    IsSupportedSystemTable is_supported;
    GetCountSystemTable get_count;
    uint32_t skip_start;
    uint32_t routine_delta;
    uint32_t routine_count;
    bool break_on_null;
    bool collect_null;
    std::vector<std::string> white_list;
} SystemTable;

using SystemTables = std::vector<SystemTable>;

SystemTables GetSystemTables();
bool IsTableSupported(const std::shared_ptr<WDbgArkSymCache> &sym_cache, const std::string &table_name);

// tcpip!IoctlDispatchTable
uint32_t GetTcpipIoctlDispatchTableCount();

// http!UlIoctlTable
uint32_t GetHttpUlIoctlTableCount();

// http!UxIoctlTable
uint32_t GetHttpUxIoctlTableCount();

// srv!*DispatchTable
// srv!SrvSmbDispatchTable
uint32_t GetSrvSmbDispatchTableCount();
// srv!SrvTransaction2DispatchTable
uint32_t GetSrvTransaction2DispatchTableCount();
// srv!SrvNtTransactionDispatchTable
uint32_t GetSrvNtTransactionDispatchTableCount();
// srv!SrvApiDispatchTable
uint32_t GetSrvApiDispatchTableCount();

// storport!StorportExtensionTable
uint32_t GetStorportExtensionTableCount();

EXT_COMMAND(wa_systables, "Output various kernel-mode system tables", "") {
    RequireKernelMode();

    if ( !Init() ) {
        throw ExtStatusException(S_OK, "global init failed");
    }

    const auto system_tables = GetSystemTables();

    try {
        for ( const auto& system_table : system_tables ) {
            out << wa::showplus << "Displaying " << system_table.name << endlout;

            if ( !system_table.is_supported(m_sym_cache, system_table.name) ) {
                out << wa::showplus << __FUNCTION__ << ": unsupported Windows version" << endlout;
                continue;
            }

            auto table_count = system_table.get_count();

            if ( !table_count ) {
                err << wa::showminus << __FUNCTION__ << ": unknown table count" << endlerr;
                continue;
            }

            WDbgArkMemTable table(m_sym_cache, system_table.name);

            if ( table.IsValid() ) {
                table.SetTableSkipStart(system_table.skip_start);
                table.SetTableCount(table_count);
                table.SetRoutineDelta(system_table.routine_delta);
                table.SetRoutineCount(system_table.routine_count);
                table.SetBreakOnNull(system_table.break_on_null);
                table.SetCollectNull(system_table.collect_null);
            } else {
                err << wa::showminus << __FUNCTION__ << ": failed to find " << system_table.name << endlerr;
                continue;
            }

            out << wa::showplus << system_table.name << ": " << std::hex << std::showbase;
            out << table.GetTableStart() << endlout;

            auto display = WDbgArkAnalyzeBase::Create(m_sym_cache);

            for ( const auto& entry : system_table.white_list ) {
                if ( !display->AddRangeWhiteList(entry) ) {
                    warn << wa::showqmark << __FUNCTION__ ": AddRangeWhiteList with " << entry << " failed" << endlwarn;
                }
            }

            display->PrintHeader();

            WDbgArkMemTable::WalkResult result;

            if ( table.Walk(&result) != false ) {
                for ( const auto& address : result ) {
                    display->Analyze(address, "", "");
                    display->PrintFooter();
                }
            } else {
                err << wa::showminus << __FUNCTION__ << ": failed to walk table" << endlerr;
            }

            display->PrintFooter();
        }
    } catch ( const ExtInterruptException& ) {
        throw;
    }
}

SystemTables GetSystemTables() {
    return {
        { "tcpip!IoctlDispatchTable",
          IsTableSupported,
          GetTcpipIoctlDispatchTableCount,
          g_Ext->m_PtrSize,
          2 * g_Ext->m_PtrSize,
          1,
          false,
          false,
          { "tcpip" } },

        { "http!UlIoctlTable",
          IsTableSupported,
          GetHttpUlIoctlTableCount,
          g_Ext->m_PtrSize,
          2 * g_Ext->m_PtrSize,
          1,
          false,
          false,
          { "http" } },

        { "http!UxIoctlTable",
          IsTableSupported,
          GetHttpUxIoctlTableCount,
          g_Ext->m_PtrSize,
          3 * g_Ext->m_PtrSize,
          2,
          false,
          false,
          { "http" } },

        { "srv!SrvSmbDispatchTable",
          IsTableSupported,
          GetSrvSmbDispatchTableCount,
          0,
          g_Ext->m_PtrSize,
          1,
          false,
          false,
          { "srv" } },

        { "srv!SrvTransaction2DispatchTable",
          IsTableSupported,
          GetSrvTransaction2DispatchTableCount,
          0,
          g_Ext->m_PtrSize,
          1,
          false,
          false,
          { "srv" } },

        { "srv!SrvNtTransactionDispatchTable",
          IsTableSupported,
          GetSrvNtTransactionDispatchTableCount,
          g_Ext->m_PtrSize,
          g_Ext->m_PtrSize,
          1,
          false,
          false,
          { "srv" } },

        { "srv!SrvApiDispatchTable",
          IsTableSupported,
          GetSrvApiDispatchTableCount,
          0,
          g_Ext->m_PtrSize,
          1,
          false,
          true,
          { "srv" } },

        { "storport!StorportExtensionTable",
          IsTableSupported,
          GetStorportExtensionTableCount,
          g_Ext->m_PtrSize,
          g_Ext->m_PtrSize,
          1,
          false,
          false,
          { "storport" } }
    };
}

bool IsTableSupported(const std::shared_ptr<WDbgArkSymCache> &sym_cache, const std::string &table_name) {
    uint64_t offset = 0ULL;

    if ( !sym_cache->GetSymbolOffset(table_name, true, &offset) ) {
        return false;
    }

    return (offset != 0ULL);
}

// tcpip!IoctlDispatchTable
uint32_t GetTcpipIoctlDispatchTableCount() {
    WDbgArkSystemVer system_ver;

    if ( !system_ver.IsInited() ) {
        return 0;
    }

    if ( system_ver.IsBuildInRangeStrict(VISTA_RTM_VER, VISTA_SP2_VER) ) {
        return 4;
    } else if ( system_ver.GetStrictVer() >= W7RTM_VER ) {
        return 5;
    }

    return 0;
}

// HTTP!UlIoctlTable
uint32_t GetHttpUlIoctlTableCount() {
    WDbgArkSystemVer system_ver;

    if ( !system_ver.IsInited() ) {
        return 0;
    }

    if ( system_ver.IsBuildInRangeStrict(WXP_VER, W8RTM_VER) ) {
        return 30;
    } else if ( system_ver.GetStrictVer() == W81RTM_VER ) {
        return 31;
    } else if ( system_ver.GetStrictVer() == W10RTM_VER ) {
        return 32;
    }

    return 0;
}

// HTTP!UxIoctlTable
uint32_t GetHttpUxIoctlTableCount() {
    WDbgArkSystemVer system_ver;

    if ( !system_ver.IsInited() ) {
        return 0;
    }

    if ( system_ver.IsBuildInRangeStrict(W10TH2_VER, W10RS1_VER) ) {
        return 32;
    } else if ( system_ver.GetStrictVer() == W10RS2_VER ) {
        return 34;
    } else if ( system_ver.GetStrictVer() >= W10RS3_VER ) {
        return 35;
    }

    return 0;
}

// srv!*DispatchTable
// srv!SrvSmbDispatchTable
uint32_t GetSrvSmbDispatchTableCount() {
    WDbgArkSystemVer system_ver;

    if ( !system_ver.IsInited() ) {
        return 0;
    }

    if ( system_ver.IsBuildInRangeStrict(WXP_VER, W2K3_VER) ) {
        return 54;
    } else if ( system_ver.GetStrictVer() >= VISTA_RTM_VER ) {
        return 49;
    }

    return 0;
}

// srv!SrvTransaction2DispatchTable
uint32_t GetSrvTransaction2DispatchTableCount() {
    WDbgArkSystemVer system_ver;

    if ( !system_ver.IsInited() ) {
        return 0;
    }

    if ( system_ver.GetStrictVer() >= WXP_VER ) {
        return 18;
    }

    return 0;
}

// srv!SrvNtTransactionDispatchTable
uint32_t GetSrvNtTransactionDispatchTableCount() {
    WDbgArkSystemVer system_ver;

    if ( !system_ver.IsInited() ) {
        return 0;
    }

    if ( system_ver.GetStrictVer() == WXP_VER ) {
        return 24;
    } else if ( system_ver.GetStrictVer() == W2K3_VER ) {
        return 8;
    } else if ( system_ver.GetStrictVer() >= VISTA_RTM_VER ) {
        return 9;
    }

    return 0;
}

// srv!SrvApiDispatchTable
uint32_t GetSrvApiDispatchTableCount() {
    return 15;
}

// storport!StorportExtensionTable
uint32_t GetStorportExtensionTableCount() {
    return 10;
}

}   // namespace wa
