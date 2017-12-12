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

//////////////////////////////////////////////////////////////////////////
//  Include this after "#define EXT_CLASS WDbgArk" only
//////////////////////////////////////////////////////////////////////////

#if _MSC_VER > 1000
#pragma once
#endif

#ifndef OBJHELPER_HPP_
#define OBJHELPER_HPP_

#include <engextcpp.hpp>

#include <string>
#include <sstream>
#include <utility>
#include <map>
#include <vector>
#include <memory>
#include <array>

#include "./ddk.h"
#include "symcache.hpp"
#include "strings.hpp"

namespace wa {

uint64_t ExFastRefGetObject(uint64_t fast_ref);

//////////////////////////////////////////////////////////////////////////
// base object manager helper class
//////////////////////////////////////////////////////////////////////////
class WDbgArkObjHelper {
 public:
    typedef struct ObjectInfoTag {
        ExtRemoteTyped object;
        ExtRemoteTyped directory_object;
        std::string full_path;
        std::string obj_name;
        std::string type_name;
    } ObjectInfo;

    using ObjectsInformation = std::map<uint64_t, ObjectInfo>;          // offset : ObjectInfo
    using ObjectsInfoResult = std::pair<HRESULT, ObjectsInformation>;   // result : ObjectsInformation

 public:
    explicit WDbgArkObjHelper(const std::shared_ptr<WDbgArkSymCache> &sym_cache);
    WDbgArkObjHelper() = delete;
    virtual ~WDbgArkObjHelper() = default;

    bool IsInited(void) const { return m_inited; }

    std::pair<HRESULT, ExtRemoteTyped> GetObjectHeader(const ExtRemoteTyped &object);
    std::pair<HRESULT, std::string> GetObjectName(const ExtRemoteTyped &object);
    std::pair<HRESULT, ExtRemoteTyped> GetObjectType(const ExtRemoteTyped &object);
    std::pair<HRESULT, std::string> GetObjectTypeName(const ExtRemoteTyped &object);
    ObjectsInfoResult GetObjectsInfo(const uint64_t directory_address = 0ULL,
                                     const std::string &root_path = R"(\)",
                                     const bool recursive = false);
    uint64_t FindObjectByName(const std::string &object_name,
                              const uint64_t directory_address = 0ULL,
                              const std::string &root_path = R"(\)",
                              const bool recursive = false);

 protected:
    bool HasObjectHeaderNameInfo(const ExtRemoteTyped &object_header) const;
    std::pair<HRESULT, ExtRemoteTyped> GetObjectHeaderNameInfo(const ExtRemoteTyped &object_header);

 protected:
    bool m_inited = false;
    bool m_object_header_old = true;
    uint64_t m_ObpInfoMaskToOffset = 0ULL;
    uint64_t m_ObTypeIndexTableOffset = 0ULL;
    uint8_t m_ObHeaderCookie = 0;
    std::shared_ptr<WDbgArkSymCache> m_sym_cache{ nullptr };
};
//////////////////////////////////////////////////////////////////////////
// driver object helper class
//////////////////////////////////////////////////////////////////////////
class WDbgArkDrvObjHelper : public WDbgArkObjHelper {
 public:
    using TableEntry = std::pair<uint64_t, std::string>;   // offset : routine name
    using Table = std::vector<TableEntry>;

    explicit WDbgArkDrvObjHelper(const std::shared_ptr<WDbgArkSymCache> &sym_cache, const ExtRemoteTyped &driver);
    WDbgArkDrvObjHelper() = delete;

    Table GetMajorTable();
    Table GetFastIoTable();
    Table GetFsFilterCbTable();

 protected:
    ExtRemoteTyped m_driver;

    std::array<std::string, 28> m_major_table_name = {
        make_string(IRP_MJ_CREATE),
        make_string(IRP_MJ_CREATE_NAMED_PIPE),
        make_string(IRP_MJ_CLOSE),
        make_string(IRP_MJ_READ),
        make_string(IRP_MJ_WRITE),
        make_string(IRP_MJ_QUERY_INFORMATION),
        make_string(IRP_MJ_SET_INFORMATION),
        make_string(IRP_MJ_QUERY_EA),
        make_string(IRP_MJ_SET_EA),
        make_string(IRP_MJ_FLUSH_BUFFERS),
        make_string(IRP_MJ_QUERY_VOLUME_INFORMATION),
        make_string(IRP_MJ_SET_VOLUME_INFORMATION),
        make_string(IRP_MJ_DIRECTORY_CONTROL),
        make_string(IRP_MJ_FILE_SYSTEM_CONTROL),
        make_string(IRP_MJ_DEVICE_CONTROL),
        make_string(IRP_MJ_INTERNAL_DEVICE_CONTROL),
        make_string(IRP_MJ_SHUTDOWN),
        make_string(IRP_MJ_LOCK_CONTROL),
        make_string(IRP_MJ_CLEANUP),
        make_string(IRP_MJ_CREATE_MAILSLOT),
        make_string(IRP_MJ_QUERY_SECURITY),
        make_string(IRP_MJ_SET_SECURITY),
        make_string(IRP_MJ_POWER),
        make_string(IRP_MJ_SYSTEM_CONTROL),
        make_string(IRP_MJ_DEVICE_CHANGE),
        make_string(IRP_MJ_QUERY_QUOTA),
        make_string(IRP_MJ_SET_QUOTA),
        make_string(IRP_MJ_PNP)
    };

    std::array<std::string, 27> m_fast_io_table_name = {
        make_string(FastIoCheckIfPossible),
        make_string(FastIoRead),
        make_string(FastIoWrite),
        make_string(FastIoQueryBasicInfo),
        make_string(FastIoQueryStandardInfo),
        make_string(FastIoLock),
        make_string(FastIoUnlockSingle),
        make_string(FastIoUnlockAll),
        make_string(FastIoUnlockAllByKey),
        make_string(FastIoDeviceControl),
        make_string(AcquireFileForNtCreateSection),
        make_string(ReleaseFileForNtCreateSection),
        make_string(FastIoDetachDevice),
        make_string(FastIoQueryNetworkOpenInfo),
        make_string(AcquireForModWrite),
        make_string(MdlRead),
        make_string(MdlReadComplete),
        make_string(PrepareMdlWrite),
        make_string(MdlWriteComplete),
        make_string(FastIoReadCompressed),
        make_string(FastIoWriteCompressed),
        make_string(MdlReadCompleteCompressed),
        make_string(MdlWriteCompleteCompressed),
        make_string(FastIoQueryOpen),
        make_string(ReleaseForModWrite),
        make_string(AcquireForCcFlush),
        make_string(ReleaseForCcFlush)
    };

    std::array<std::string, 12> m_fs_filter_cb_table_name = {
        make_string(PreAcquireForSectionSynchronization),
        make_string(PostAcquireForSectionSynchronization),
        make_string(PreReleaseForSectionSynchronization),
        make_string(PostReleaseForSectionSynchronization),
        make_string(PreAcquireForCcFlush),
        make_string(PostAcquireForCcFlush),
        make_string(PreReleaseForCcFlush),
        make_string(PostReleaseForCcFlush),
        make_string(PreAcquireForModifiedPageWriter),
        make_string(PostAcquireForModifiedPageWriter),
        make_string(PreReleaseForModifiedPageWriter),
        make_string(PostReleaseForModifiedPageWriter)
    };
};
//////////////////////////////////////////////////////////////////////////
// class driver object helper class
//////////////////////////////////////////////////////////////////////////
class WDbgArkClassDrvObjHelper : public WDbgArkDrvObjHelper {
 public:
    explicit WDbgArkClassDrvObjHelper(const std::shared_ptr<WDbgArkSymCache> &sym_cache, const ExtRemoteTyped &driver);
    WDbgArkClassDrvObjHelper() = delete;

    ExtRemoteTyped Get() const { return m_class_driver_extension; }
    std::string GetClassExtensionDmlCommand() const;

    bool HasClassDriverExtension() const { return m_has_class_driver_extension; }
    ExtRemoteTyped Field(const std::string &field) { return m_class_driver_extension.Field(field.c_str()); }

    Table GetInitDataTable();
    
    // FdoData
    Table GetInitDataFdoDataTable();
    Table GetInitDataFdoDataWmiTable();

    // PdoData
    Table GetInitDataPdoDataTable();
    Table GetInitDataPdoDataWmiTable();

    Table GetDeviceMajorFunctionTable();
    Table GetMpDeviceMajorFunctionTable();

 private:
    bool GetClassDriverExtension();

 private:
    uint64_t m_class_clientid = 0ULL;
    bool m_has_class_driver_extension = false;
    ExtRemoteTyped m_class_driver_extension;

    std::array<std::string, 6> m_init_data_table_name = {
        make_string(InitData.ClassAddDevice),
        make_string(InitData.ClassEnumerateDevice),
        make_string(InitData.ClassQueryId),
        make_string(InitData.ClassStartIo),
        make_string(InitData.ClassUnload),
        make_string(InitData.ClassTick)
    };

    std::array<std::string, 11> m_init_data_fdo_data_table_name = {
        make_string(InitData.FdoData.ClassError),
        make_string(InitData.FdoData.ClassReadWriteVerification),
        make_string(InitData.FdoData.ClassDeviceControl),
        make_string(InitData.FdoData.ClassShutdownFlush),
        make_string(InitData.FdoData.ClassCreateClose),
        make_string(InitData.FdoData.ClassInitDevice),
        make_string(InitData.FdoData.ClassStartDevice),
        make_string(InitData.FdoData.ClassPowerDevice),
        make_string(InitData.FdoData.ClassStopDevice),
        make_string(InitData.FdoData.ClassRemoveDevice),
        make_string(InitData.FdoData.ClassQueryPnpCapabilities)
    };

    std::array<std::string, 6> m_init_data_fdo_data_wmi_table_name = {
        make_string(InitData.FdoData.ClassWmiInfo.ClassQueryWmiRegInfo),
        make_string(InitData.FdoData.ClassWmiInfo.ClassQueryWmiDataBlock),
        make_string(InitData.FdoData.ClassWmiInfo.ClassSetWmiDataBlock),
        make_string(InitData.FdoData.ClassWmiInfo.ClassSetWmiDataItem),
        make_string(InitData.FdoData.ClassWmiInfo.ClassExecuteWmiMethod),
        make_string(InitData.FdoData.ClassWmiInfo.ClassWmiFunctionControl)
    };

    std::array<std::string, 11> m_init_data_pdo_data_table_name = {
        make_string(InitData.PdoData.ClassError),
        make_string(InitData.PdoData.ClassReadWriteVerification),
        make_string(InitData.PdoData.ClassDeviceControl),
        make_string(InitData.PdoData.ClassShutdownFlush),
        make_string(InitData.PdoData.ClassCreateClose),
        make_string(InitData.PdoData.ClassInitDevice),
        make_string(InitData.PdoData.ClassStartDevice),
        make_string(InitData.PdoData.ClassPowerDevice),
        make_string(InitData.PdoData.ClassStopDevice),
        make_string(InitData.PdoData.ClassRemoveDevice),
        make_string(InitData.PdoData.ClassQueryPnpCapabilities)
    };

    std::array<std::string, 6> m_init_data_pdo_data_wmi_table_name = {
        make_string(InitData.PdoData.ClassWmiInfo.ClassQueryWmiRegInfo),
        make_string(InitData.PdoData.ClassWmiInfo.ClassQueryWmiDataBlock),
        make_string(InitData.PdoData.ClassWmiInfo.ClassSetWmiDataBlock),
        make_string(InitData.PdoData.ClassWmiInfo.ClassSetWmiDataItem),
        make_string(InitData.PdoData.ClassWmiInfo.ClassExecuteWmiMethod),
        make_string(InitData.PdoData.ClassWmiInfo.ClassWmiFunctionControl)
    };
};

}   // namespace wa

#endif  // OBJHELPER_HPP_
