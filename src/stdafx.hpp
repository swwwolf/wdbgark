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

#ifndef STDAFX_HPP_
#define STDAFX_HPP_

#include <windows.h>

#include <engextcpp.hpp>
#include <strsafe.h>
#include <dbghelp.h>

#include <time.h>
#include <direct.h>
#include <stdint.h>
#include <comip.h>

#if defined(_DEBUG)
    #include <stdlib.h>
    #include <crtdbg.h>
#endif  // _DEBUG

#include <bprinter/table_printer.h>
#include <udis86.h>

#include <cstdio>
#include <cmath>
#include <cctype>
#include <climits>
#include <cstdlib>
#include <cstring>

#include <new>

#include <memory>
#include <utility>
#include <regex>
#include <functional>
#include <algorithm>

#include <mutex>
#include <atomic>

#include <string>
#include <sstream>
#include <fstream>

#include <iostream>
#include <iomanip>

#include <vector>
#include <map>
#include <unordered_map>
#include <set>
#include <tuple>
#include <array>

#endif  // STDAFX_HPP_
