cmake_minimum_required(VERSION 3.15)
project(MCPx64dbg)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

execute_process(
    COMMAND git rev-parse --short=12 HEAD
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    OUTPUT_VARIABLE MCP_BRIDGE_GIT_ID
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)
if(NOT MCP_BRIDGE_GIT_ID)
    set(MCP_BRIDGE_GIT_ID "unknown")
endif()
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${CMAKE_SOURCE_DIR}/src/MCPx64dbg.cpp"
    "${CMAKE_SOURCE_DIR}/src/bridge_core.cpp"
    "${CMAKE_SOURCE_DIR}/src/bridge_core.hpp"
    "${CMAKE_SOURCE_DIR}/src/exception_policy_core.cpp"
    "${CMAKE_SOURCE_DIR}/src/exception_policy_core.hpp"
    "${CMAKE_SOURCE_DIR}/src/file_identity.cpp"
    "${CMAKE_SOURCE_DIR}/src/file_identity.hpp"
    "${CMAKE_SOURCE_DIR}/src/launch_core.cpp"
    "${CMAKE_SOURCE_DIR}/src/launch_core.hpp"
    "${CMAKE_SOURCE_DIR}/src/launch_runtime.cpp"
    "${CMAKE_SOURCE_DIR}/src/launch_runtime.hpp"
    "${CMAKE_SOURCE_DIR}/src/route_policy.inc"
    "${CMAKE_SOURCE_DIR}/src/child_broker_core.cpp"
    "${CMAKE_SOURCE_DIR}/src/child_broker_core.hpp"
    "${CMAKE_SOURCE_DIR}/src/http_parser_core.cpp"
    "${CMAKE_SOURCE_DIR}/src/http_parser_core.hpp"
    "${CMAKE_SOURCE_DIR}/src/request_dispatcher_core.cpp"
    "${CMAKE_SOURCE_DIR}/src/request_dispatcher_core.hpp"
    "${CMAKE_SOURCE_DIR}/src/mutation_transaction_core.cpp"
    "${CMAKE_SOURCE_DIR}/src/mutation_transaction_core.hpp"
)
file(SHA256 "${CMAKE_SOURCE_DIR}/src/MCPx64dbg.cpp" MCP_BRIDGE_MAIN_SHA256)
file(SHA256 "${CMAKE_SOURCE_DIR}/src/bridge_core.cpp" MCP_BRIDGE_CORE_SHA256)
file(SHA256 "${CMAKE_SOURCE_DIR}/src/bridge_core.hpp" MCP_BRIDGE_HEADER_SHA256)
file(SHA256 "${CMAKE_SOURCE_DIR}/src/exception_policy_core.cpp" MCP_EXCEPTION_POLICY_CORE_SHA256)
file(SHA256 "${CMAKE_SOURCE_DIR}/src/exception_policy_core.hpp" MCP_EXCEPTION_POLICY_HEADER_SHA256)
file(SHA256 "${CMAKE_SOURCE_DIR}/src/file_identity.cpp" MCP_FILE_IDENTITY_CORE_SHA256)
file(SHA256 "${CMAKE_SOURCE_DIR}/src/file_identity.hpp" MCP_FILE_IDENTITY_HEADER_SHA256)
file(SHA256 "${CMAKE_SOURCE_DIR}/src/launch_core.cpp" MCP_LAUNCH_CORE_SHA256)
file(SHA256 "${CMAKE_SOURCE_DIR}/src/launch_core.hpp" MCP_LAUNCH_HEADER_SHA256)
file(SHA256 "${CMAKE_SOURCE_DIR}/src/launch_runtime.cpp" MCP_LAUNCH_RUNTIME_SHA256)
file(SHA256 "${CMAKE_SOURCE_DIR}/src/launch_runtime.hpp" MCP_LAUNCH_RUNTIME_HEADER_SHA256)
file(SHA256 "${CMAKE_SOURCE_DIR}/src/route_policy.inc" MCP_ROUTE_POLICY_SHA256)
file(SHA256 "${CMAKE_SOURCE_DIR}/src/child_broker_core.cpp" MCP_CHILD_BROKER_CORE_SHA256)
file(SHA256 "${CMAKE_SOURCE_DIR}/src/child_broker_core.hpp" MCP_CHILD_BROKER_HEADER_SHA256)
file(SHA256 "${CMAKE_SOURCE_DIR}/src/http_parser_core.cpp" MCP_HTTP_PARSER_CORE_SHA256)
file(SHA256 "${CMAKE_SOURCE_DIR}/src/http_parser_core.hpp" MCP_HTTP_PARSER_HEADER_SHA256)
file(SHA256 "${CMAKE_SOURCE_DIR}/src/request_dispatcher_core.cpp" MCP_REQUEST_DISPATCHER_CORE_SHA256)
file(SHA256 "${CMAKE_SOURCE_DIR}/src/request_dispatcher_core.hpp" MCP_REQUEST_DISPATCHER_HEADER_SHA256)
file(SHA256 "${CMAKE_SOURCE_DIR}/src/mutation_transaction_core.cpp" MCP_MUTATION_CORE_SHA256)
file(SHA256 "${CMAKE_SOURCE_DIR}/src/mutation_transaction_core.hpp" MCP_MUTATION_HEADER_SHA256)
string(SHA256 MCP_BRIDGE_SOURCE_SHA256
    "${MCP_BRIDGE_MAIN_SHA256}:${MCP_BRIDGE_CORE_SHA256}:${MCP_BRIDGE_HEADER_SHA256}:${MCP_EXCEPTION_POLICY_CORE_SHA256}:${MCP_EXCEPTION_POLICY_HEADER_SHA256}:${MCP_FILE_IDENTITY_CORE_SHA256}:${MCP_FILE_IDENTITY_HEADER_SHA256}:${MCP_LAUNCH_CORE_SHA256}:${MCP_LAUNCH_HEADER_SHA256}:${MCP_LAUNCH_RUNTIME_SHA256}:${MCP_LAUNCH_RUNTIME_HEADER_SHA256}:${MCP_ROUTE_POLICY_SHA256}:${MCP_CHILD_BROKER_CORE_SHA256}:${MCP_CHILD_BROKER_HEADER_SHA256}:${MCP_HTTP_PARSER_CORE_SHA256}:${MCP_HTTP_PARSER_HEADER_SHA256}:${MCP_REQUEST_DISPATCHER_CORE_SHA256}:${MCP_REQUEST_DISPATCHER_HEADER_SHA256}:${MCP_MUTATION_CORE_SHA256}:${MCP_MUTATION_HEADER_SHA256}")
string(SUBSTRING "${MCP_BRIDGE_SOURCE_SHA256}" 0 16 MCP_BRIDGE_SOURCE_ID)
string(SUBSTRING "${MCP_ROUTE_POLICY_SHA256}" 0 16 MCP_ROUTE_POLICY_ID)

option(BUILD_BOTH_ARCHES "Build both 32-bit and 64-bit plugins from this CMake project" ON)
option(X64DBG_DOWNLOAD_SDK "Download x64dbg-pluginsdk.zip when debugger import libs are missing or stub-sized" ON)

set(X64DBG_SDK_PINNED_URL
    "https://github.com/x64dbg/x64dbg/releases/download/2025.08.19/x64dbg-pluginsdk.zip")
set(X64DBG_SDK_PINNED_SHA256
    "983f2588973a06920f90b75aa1bec9e1a847a3ab40a7b7f6a5b1eddc9b72cc48")

if(BUILD_BOTH_ARCHES AND MSVC)
    include(ExternalProject)
    message(STATUS "Configuring superbuild to produce both dp32 and dp64")

    ExternalProject_Add(plugin32
        SOURCE_DIR ${CMAKE_SOURCE_DIR}
        BINARY_DIR ${CMAKE_BINARY_DIR}/build32
        CMAKE_GENERATOR "${CMAKE_GENERATOR}"
        CMAKE_GENERATOR_PLATFORM Win32
        BUILD_ALWAYS 1
        CMAKE_ARGS
            -DCMAKE_BUILD_TYPE=$<IF:$<CONFIG:>,${CMAKE_BUILD_TYPE},Release>
            -DBUILD_BOTH_ARCHES=OFF
            -DX64DBG_DOWNLOAD_SDK=${X64DBG_DOWNLOAD_SDK}
        INSTALL_COMMAND ""
    )

    ExternalProject_Add(plugin64
        SOURCE_DIR ${CMAKE_SOURCE_DIR}
        BINARY_DIR ${CMAKE_BINARY_DIR}/build64
        CMAKE_GENERATOR "${CMAKE_GENERATOR}"
        CMAKE_GENERATOR_PLATFORM x64
        BUILD_ALWAYS 1
        CMAKE_ARGS
            -DCMAKE_BUILD_TYPE=$<IF:$<CONFIG:>,${CMAKE_BUILD_TYPE},Release>
            -DBUILD_BOTH_ARCHES=OFF
            -DX64DBG_DOWNLOAD_SDK=${X64DBG_DOWNLOAD_SDK}
        INSTALL_COMMAND ""
    )

    add_custom_target(all_plugins DEPENDS plugin32 plugin64)

    message(STATUS "Use 'cmake --build . --target all_plugins' to build both dp32 and dp64")

    return()
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(PLUGIN_EXT ".dp64")
    set(ARCH_BITS 64)
    set(ARCH_SUFFIX "_x64")
    set(X64DBG_DBG_IMPORT_LIB "x64dbg.lib")
else()
    set(PLUGIN_EXT ".dp32")
    set(ARCH_BITS 32)
    set(ARCH_SUFFIX "_x86")
    set(X64DBG_DBG_IMPORT_LIB "x32dbg.lib")
endif()

set(X64DBG_DEPS_DIR "${CMAKE_SOURCE_DIR}/deps")
set(_x64dbg_psdk_zip "${CMAKE_BINARY_DIR}/x64dbg-pluginsdk.zip")
file(MAKE_DIRECTORY "${X64DBG_DEPS_DIR}")
# x86/x64 superbuild children share the source dependency directory.  Serialize
# download/extraction so a clean parallel build cannot consume a partial SDK.
file(LOCK "${X64DBG_DEPS_DIR}/.x64dbg-sdk.lock" GUARD PROCESS TIMEOUT 300)

# --- Ensure full Plugin SDK (headers + import libs), not runtime stub .lib files (~2 KB). ---
if(NOT EXISTS "${X64DBG_DEPS_DIR}/bridgemain.h")
    if(X64DBG_DOWNLOAD_SDK)
        message(STATUS "Downloading x64dbg Plugin SDK (headers)...")
        file(DOWNLOAD "${X64DBG_SDK_PINNED_URL}" "${_x64dbg_psdk_zip}"
            EXPECTED_HASH "SHA256=${X64DBG_SDK_PINNED_SHA256}"
            SHOW_PROGRESS STATUS _dl)
        if(NOT _dl EQUAL 0)
            message(FATAL_ERROR "Plugin SDK download failed (status: ${_dl})")
        endif()
        execute_process(COMMAND ${CMAKE_COMMAND} -E tar xf "${_x64dbg_psdk_zip}"
            WORKING_DIRECTORY "${X64DBG_DEPS_DIR}" RESULT_VARIABLE _ex)
        if(NOT _ex EQUAL 0)
            message(FATAL_ERROR "Plugin SDK extract failed (exit ${_ex})")
        endif()
    endif()
    if(NOT EXISTS "${X64DBG_DEPS_DIR}/bridgemain.h")
        message(FATAL_ERROR
            "Plugin SDK missing: ${X64DBG_DEPS_DIR}/bridgemain.h\n"
            "  Extract x64dbg-pluginsdk.zip into deps/, or reconfigure with -DX64DBG_DOWNLOAD_SDK=ON")
    endif()
endif()

set(_dbg_lib "${X64DBG_DEPS_DIR}/${X64DBG_DBG_IMPORT_LIB}")
set(_need_sdk_fetch FALSE)
if(NOT EXISTS "${_dbg_lib}")
    set(_need_sdk_fetch TRUE)
else()
    file(SIZE "${_dbg_lib}" _dbg_lib_sz)
    # Official imports are ~90–120 KB each; runtime / stub copies are only a few KB.
    if(_dbg_lib_sz LESS 20000)
        set(_need_sdk_fetch TRUE)
    endif()
endif()

if(_need_sdk_fetch)
    if(X64DBG_DOWNLOAD_SDK)
        message(STATUS "Downloading x64dbg Plugin SDK (full ${_dbg_lib})...")
        file(DOWNLOAD "${X64DBG_SDK_PINNED_URL}" "${_x64dbg_psdk_zip}"
            EXPECTED_HASH "SHA256=${X64DBG_SDK_PINNED_SHA256}"
            SHOW_PROGRESS STATUS _dl2)
        if(NOT _dl2 EQUAL 0)
            message(FATAL_ERROR "Plugin SDK download failed (status: ${_dl2})")
        endif()
        execute_process(COMMAND ${CMAKE_COMMAND} -E tar xf "${_x64dbg_psdk_zip}"
            WORKING_DIRECTORY "${X64DBG_DEPS_DIR}" RESULT_VARIABLE _ex2)
        if(NOT _ex2 EQUAL 0)
            message(FATAL_ERROR "Plugin SDK extract failed (exit ${_ex2})")
        endif()
    endif()
    if(NOT EXISTS "${_dbg_lib}")
        message(FATAL_ERROR
            "Missing ${_dbg_lib}\n"
            "  Use the full x64dbg-pluginsdk.zip from a release (not runtime DLL folders).\n"
            "  Or: cmake -S . -B build -DX64DBG_DOWNLOAD_SDK=ON")
    endif()
    file(SIZE "${_dbg_lib}" _dbg_lib_sz2)
    if(_dbg_lib_sz2 LESS 20000)
        message(FATAL_ERROR
            "${_dbg_lib} is only ${_dbg_lib_sz2} bytes (stub). Need the real import library from\n"
            "  x64dbg-pluginsdk.zip (~90–120 KB). Replace deps/x32dbg.lib and x64dbg.lib, or use:\n"
            "  cmake -S . -B build -DX64DBG_DOWNLOAD_SDK=ON")
    endif()
endif()

include_directories(
    ${X64DBG_DEPS_DIR}
    ${CMAKE_SOURCE_DIR}/include
)
if(EXISTS "${X64DBG_DEPS_DIR}/nlohmann")
    include_directories(${X64DBG_DEPS_DIR}/nlohmann)
endif()

file(GLOB SOURCES "src/*.cpp")
add_library(${PROJECT_NAME} SHARED ${SOURCES})
target_compile_definitions(${PROJECT_NAME} PRIVATE
    MCP_BRIDGE_BUILD_ID="${MCP_BRIDGE_GIT_ID}"
    MCP_BRIDGE_SOURCE_ID="${MCP_BRIDGE_SOURCE_ID}"
    MCP_ROUTE_POLICY_ID="${MCP_ROUTE_POLICY_ID}"
)

set_target_properties(${PROJECT_NAME} PROPERTIES
    PREFIX ""
    OUTPUT_NAME "${PROJECT_NAME}"
    SUFFIX "${PLUGIN_EXT}"
)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    target_compile_definitions(${PROJECT_NAME} PRIVATE _WIN64)
else()
    target_compile_definitions(${PROJECT_NAME} PRIVATE _WIN32)
endif()

# /EHa enables asynchronous (structured) exception handling so _set_se_translator
# can turn an access violation inside a request handler into a catchable C++
# exception. Without it, a bad guest pointer would crash all of x64dbg instead of
# returning HTTP 500. Replace CMake's default /EHsc to avoid a conflict warning.
if(MSVC)
    string(REGEX REPLACE "/EH[a-z]+" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
    target_compile_options(${PROJECT_NAME} PRIVATE /EHa)
    # Link the CRT statically so the built plugin has no external VCRuntime
    # dependency and loads on a clean machine (requires CMP0091, default >= 3.15).
    set_property(TARGET ${PROJECT_NAME} PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    file(GLOB_RECURSE X64DBG_SDK_IMPORT_LIBS CONFIGURE_DEPENDS
        "${X64DBG_DEPS_DIR}/*_x64.lib"
        "${X64DBG_DEPS_DIR}/x64*.lib"
    )
else()
    file(GLOB_RECURSE X64DBG_SDK_IMPORT_LIBS CONFIGURE_DEPENDS
        "${X64DBG_DEPS_DIR}/*_x86.lib"
        "${X64DBG_DEPS_DIR}/x32*.lib"
    )
endif()
if(NOT X64DBG_SDK_IMPORT_LIBS)
    message(FATAL_ERROR
        "No SDK .lib files matched for this architecture under ${X64DBG_DEPS_DIR}\n"
        "  Re-extract x64dbg-pluginsdk.zip or use -DX64DBG_DOWNLOAD_SDK=ON")
endif()

target_link_directories(${PROJECT_NAME} PRIVATE ${X64DBG_DEPS_DIR})
target_link_libraries(${PROJECT_NAME} PRIVATE
    ws2_32 winhttp ole32 dbghelp bcrypt advapi32 shell32
    ${X64DBG_SDK_IMPORT_LIBS}
)

include(CTest)
if(BUILD_TESTING)
    add_executable(bridge_core_native_tests
        tests/native_bridge_core_tests.cpp
        src/bridge_core.cpp
        src/exception_policy_core.cpp
        src/file_identity.cpp
        src/launch_core.cpp
        src/child_broker_core.cpp
        src/http_parser_core.cpp
        src/request_dispatcher_core.cpp
    )
    target_include_directories(bridge_core_native_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(bridge_core_native_tests PRIVATE ws2_32 ole32 shell32 bcrypt)
    if(MSVC)
        target_compile_options(bridge_core_native_tests PRIVATE /EHsc /W4 /WX)
    endif()
    add_test(NAME bridge_core_native COMMAND bridge_core_native_tests)

    add_executable(launch_runtime_fixture
        tests/fixtures/e2e/launch_contract.c
    )
    if(MSVC)
        target_compile_options(launch_runtime_fixture PRIVATE /W4 /WX)
    endif()

    add_executable(launch_runtime_native_tests
        tests/native_launch_runtime_tests.cpp
        src/file_identity.cpp
        src/launch_core.cpp
        src/launch_runtime.cpp
    )
    target_include_directories(launch_runtime_native_tests PRIVATE
        ${CMAKE_SOURCE_DIR}/src
    )
    target_link_libraries(launch_runtime_native_tests PRIVATE bcrypt)
    add_dependencies(launch_runtime_native_tests launch_runtime_fixture)
    if(MSVC)
        target_compile_options(launch_runtime_native_tests PRIVATE /EHsc /W4 /WX)
    endif()
    add_test(NAME launch_runtime_native COMMAND launch_runtime_native_tests)

    add_executable(mutation_transaction_native_tests
        tests/native_mutation_transaction_tests.cpp
        src/mutation_transaction_core.cpp
    )
    target_include_directories(mutation_transaction_native_tests PRIVATE
        ${CMAKE_SOURCE_DIR}/src
    )
    if(MSVC)
        target_compile_options(mutation_transaction_native_tests PRIVATE /EHsc /W4 /WX /permissive-)
    endif()
    add_test(NAME mutation_transaction_native COMMAND mutation_transaction_native_tests)
endif()

add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo ""
    COMMAND ${CMAKE_COMMAND} -E echo "=== Plugin build complete ==="
    COMMAND ${CMAKE_COMMAND} -E echo "Plugin built at: ${CMAKE_BINARY_DIR}/${CMAKE_CFG_INTDIR}/${PROJECT_NAME}${PLUGIN_EXT}"
    COMMAND ${CMAKE_COMMAND} -E echo "Install manually to: $ENV{ProgramFiles}/x64dbg/release/x${ARCH_BITS}/plugins/${PROJECT_NAME}${PLUGIN_EXT}"
    COMMAND ${CMAKE_COMMAND} -E echo "================================="
)
