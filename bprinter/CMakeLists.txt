cmake_minimum_required(VERSION 2.8)
project(bprinter)

# Boost Karma (part of Boost Spirir) has ability to handle output
option(USE_BOOST_KARMA "Use Boost Karma for output instead of doing it ourselves?" ON)
if(USE_BOOST_KARMA)
  find_package(Boost)
  if (Boost_FOUND)
    add_definitions("-DUSE_BOOST_KARMA")
  endif (Boost_FOUND)
endif(USE_BOOST_KARMA)

include_directories(${PROJECT_SOURCE_DIR}/include)
add_library(bprinter STATIC
  include/bprinter/table_printer.h
  include/bprinter/impl/table_printer.tpp.h
  src/table_printer.cpp
)

add_executable(bprinterTest src/test_main.cxx)
target_link_libraries(bprinterTest bprinter)
