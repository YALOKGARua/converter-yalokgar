cmake_minimum_required(VERSION 3.20)
project(UniversalConverter VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(MSVC)
    add_compile_options(/W4 /permissive- /Zc:__cplusplus /std:c++latest)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -O3 -march=native)
endif()

find_package(Threads REQUIRED)
find_package(Boost REQUIRED COMPONENTS filesystem system program_options regex)
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(PkgConfig REQUIRED)

pkg_check_modules(LIBAV REQUIRED libavcodec libavformat libavutil libswscale)
pkg_check_modules(OPENCV REQUIRED opencv4)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/external
    ${Boost_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    ${LIBAV_INCLUDE_DIRS}
    ${OPENCV_INCLUDE_DIRS}
)

file(GLOB_RECURSE CORE_SOURCES "src/core/*.cpp")
file(GLOB_RECURSE MODULE_SOURCES "src/modules/*.cpp")
file(GLOB_RECURSE PLUGIN_SOURCES "src/plugins/*.cpp")
file(GLOB_RECURSE GUI_SOURCES "src/gui/*.cpp")
file(GLOB_RECURSE CLI_SOURCES "src/cli/*.cpp")
file(GLOB_RECURSE NETWORK_SOURCES "src/network/*.cpp")
file(GLOB_RECURSE DATABASE_SOURCES "src/database/*.cpp")
file(GLOB_RECURSE SECURITY_SOURCES "src/security/*.cpp")
file(GLOB_RECURSE UTILS_SOURCES "src/utils/*.cpp")

add_library(converter_core STATIC ${CORE_SOURCES})
add_library(converter_modules STATIC ${MODULE_SOURCES})
add_library(converter_plugins SHARED ${PLUGIN_SOURCES})
add_library(converter_gui STATIC ${GUI_SOURCES})
add_library(converter_network STATIC ${NETWORK_SOURCES})
add_library(converter_database STATIC ${DATABASE_SOURCES})
add_library(converter_security STATIC ${SECURITY_SOURCES})
add_library(converter_utils STATIC ${UTILS_SOURCES})

target_link_libraries(converter_core
    ${Boost_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ZLIB::ZLIB
    Threads::Threads
)

target_link_libraries(converter_modules
    converter_core
    converter_utils
    ${LIBAV_LIBRARIES}
    ${OPENCV_LIBRARIES}
)

target_link_libraries(converter_plugins
    converter_core
    converter_modules
    ${CMAKE_DL_LIBS}
)

target_link_libraries(converter_network
    converter_core
    converter_security
    ${OPENSSL_LIBRARIES}
)

target_link_libraries(converter_database
    converter_core
    ${SQLITE3_LIBRARIES}
)

target_link_libraries(converter_security
    converter_core
    ${OPENSSL_LIBRARIES}
)

add_executable(converter_cli ${CLI_SOURCES})
target_link_libraries(converter_cli
    converter_core
    converter_modules
    converter_plugins
    converter_network
    converter_database
    converter_security
    converter_utils
    ${Boost_LIBRARIES}
)

add_executable(converter_gui main_gui.cpp)
target_link_libraries(converter_gui
    converter_core
    converter_modules
    converter_plugins
    converter_gui
    converter_network
    converter_database
    converter_security
    converter_utils
)

enable_testing()
add_subdirectory(src/tests)

install(TARGETS converter_cli converter_gui
    RUNTIME DESTINATION bin
)

install(DIRECTORY configs/
    DESTINATION etc/converter
)

set(CPACK_GENERATOR "ZIP;TGZ")
set(CPACK_PACKAGE_NAME "UniversalConverter")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
include(CPack) 