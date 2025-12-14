cmake_minimum_required(VERSION 3.10.0)
project(xorstr VERSION 0.1.0 LANGUAGES CXX)

add_library(${PROJECT_NAME} INTERFACE)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>  # 用于安装后的配置
)

target_compile_features(xorstr INTERFACE cxx_std_23)

if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(${PROJECT_NAME} INTERFACE -mavx2)
    target_compile_options(${PROJECT_NAME} INTERFACE -fno-exceptions)
    target_compile_options(${PROJECT_NAME} INTERFACE -fno-unwind-tables)
    target_compile_options(${PROJECT_NAME} INTERFACE -fno-rtti)
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    target_compile_options(${PROJECT_NAME} INTERFACE /arch:AVX2)
    target_compile_options(${PROJECT_NAME} INTERFACE /EHsc)
    target_compile_options(${PROJECT_NAME} INTERFACE /D_HAS_EXCEPTIONS=0)
    target_compile_options(${PROJECT_NAME} INTERFACE /utf-8)
    target_compile_options(${PROJECT_NAME} INTERFACE "$<$<CXX_COMPILER_ID:MSVC>:/source-charset:utf-8>")
    target_compile_options(${PROJECT_NAME} INTERFACE "$<$<C_COMPILER_ID:MSVC>:/source-charset:utf-8>")
endif()

include(CTest)
enable_testing()
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
