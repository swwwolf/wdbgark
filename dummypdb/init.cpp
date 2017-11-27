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

#ifdef __cplusplus
}
#endif

//////////////////////////////////////////////////////////////////////////
// DriverEntry
//////////////////////////////////////////////////////////////////////////
NTSTATUS DriverEntry(__in DRIVER_OBJECT* DriverObject, __in PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    return STATUS_SUCCESS;
}
//////////////////////////////////////////////////////////////////////////
