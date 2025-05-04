cmake_minimum_required(VERSION 3.22)
project(HttpFilterEngine)

set(CMAKE_CXX_STANDARD 20)

set(BUILD_SHARED_LIBS OFF)

set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME ON)
set(BOOST_ALL_DYN_LINK OFF)

set(PROCESS_INFO_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
add_library(process_info STATIC
    src/process_info.cpp
)

set(EDR_BLOCKER_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
add_executable(edr_blocker
    src/edr_blocker.cpp
)

set(LOGGER_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/deps/logger/include)
add_library(logger STATIC
    deps/logger/src/logger.cpp  
)

set(WINDIVERT_LIB_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/deps/windivert-lib/include)
add_library(windivert_lib STATIC
    deps/windivert-lib/src/windivert.c  
)

FIND_PACKAGE(Threads REQUIRED)
SET(Boost_USE_MULTITHREADED ON)

find_package(Boost REQUIRED)
set(Boost_USE_STATIC_LIBS ON)

target_link_libraries(edr_blocker PUBLIC process_info logger windivert_lib ws2_32 shlwapi)
target_include_directories(edr_blocker PUBLIC ${EDR_BLOCKER_INCLUDE_DIR})
target_compile_options(edr_blocker PUBLIC /bigobj)  

target_link_libraries(logger PUBLIC boost::boost)
target_include_directories(logger PUBLIC ${LOGGER_INCLUDE_DIR})

target_include_directories(windivert_lib PUBLIC ${WINDIVERT_LIB_INCLUDE_DIR})

target_include_directories(process_info PUBLIC ${PROCESS_INFO_INCLUDE_DIR})

if(WIN32)
    target_compile_definitions(edr_blocker PUBLIC BOOST_ASIO_SEPARATE_COMPILATION WIN32_LEAN_AND_MEAN)
endif()
