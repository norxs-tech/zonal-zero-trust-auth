# =============================================================================
# CMakeLists.txt — zonal-zero-trust-authenticator
# norxs Technology LLC | (c) 2026 | https://norxs.com
#
# Supported targets:
#   Host (x86-64 Linux/macOS) — CI, unit testing, SoftwareCryptoProvider
#   ARM Cortex-A53 (QNX/Linux) — cmake -DCMAKE_TOOLCHAIN_FILE=cmake/Toolchain-A53.cmake
#   ARM Cortex-M7 (bare-metal) — cmake -DCMAKE_TOOLCHAIN_FILE=cmake/Toolchain-M7.cmake
#
# Usage:
#   mkdir build && cd build
#   cmake .. -DZZTA_BUILD_TESTS=ON -DZZTA_ENABLE_COVERAGE=ON
#   cmake --build . --target zzta_tests
#   ctest --output-on-failure
#   cmake --build . --target coverage   # produces coverage/index.html
# =============================================================================

cmake_minimum_required(VERSION 3.20)

project(zonal-zero-trust-authenticator
    VERSION     1.0.0
    DESCRIPTION "Zero-Trust SPDM Authenticator for Zonal ECUs — ISO/SAE 21434, UN R155"
    LANGUAGES   CXX
)

# ─────────────────────────────────────────────────────────────────────────────
# C++ standard enforcement (AUTOSAR C++14 mandate)
# ─────────────────────────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD          14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)  # No GNU extensions — AUTOSAR [A1-1-1]

# ─────────────────────────────────────────────────────────────────────────────
# Build options
# ─────────────────────────────────────────────────────────────────────────────
option(ZZTA_BUILD_TESTS       "Build GoogleTest unit test executable"           ON)
option(ZZTA_PRODUCTION_BUILD  "Enable production build guard (blocks mock)"     OFF)
option(ZZTA_ENABLE_ASAN       "Enable AddressSanitizer (host debug only)"       OFF)
option(ZZTA_ENABLE_UBSAN      "Enable UBSanitizer (host debug only)"            OFF)
option(ZZTA_ENABLE_COVERAGE   "Enable gcov/lcov MC/DC coverage instrumentation" OFF)
option(ZZTA_ENABLE_CLANG_TIDY "Run clang-tidy static analysis during build"     OFF)

# ─────────────────────────────────────────────────────────────────────────────
# clang-tidy integration (AUTOSAR AUTOSAR_CPP14 check set)
# ─────────────────────────────────────────────────────────────────────────────
if(ZZTA_ENABLE_CLANG_TIDY)
    find_program(CLANG_TIDY_EXE NAMES clang-tidy-15 clang-tidy-14 clang-tidy)
    if(CLANG_TIDY_EXE)
        set(CMAKE_CXX_CLANG_TIDY
            "${CLANG_TIDY_EXE}"
            "--config-file=${CMAKE_SOURCE_DIR}/.clang-tidy"
            "--header-filter=include/zzta/.*"
            "--extra-arg=-std=c++14"
        )
        message(STATUS "clang-tidy: ${CLANG_TIDY_EXE}")
    else()
        message(WARNING "ZZTA_ENABLE_CLANG_TIDY=ON but clang-tidy not found; skipping.")
    endif()
endif()

# ─────────────────────────────────────────────────────────────────────────────
# Compiler warning flags (AUTOSAR / MISRA-aligned strictness)
# ─────────────────────────────────────────────────────────────────────────────
set(ZZTA_WARN_FLAGS
    -Wall -Wextra -Wpedantic -Wshadow -Wnon-virtual-dtor -Wold-style-cast
    -Woverloaded-virtual -Wno-unused-parameter -Wconversion -Wsign-conversion
    -Wformat=2
)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    list(APPEND ZZTA_WARN_FLAGS -Wlogical-op -Wduplicated-cond -Wnull-dereference)
endif()

# ─────────────────────────────────────────────────────────────────────────────
# Coverage flags
# ─────────────────────────────────────────────────────────────────────────────
set(ZZTA_COVERAGE_FLAGS "")
if(ZZTA_ENABLE_COVERAGE AND NOT CMAKE_CROSSCOMPILING)
    set(ZZTA_COVERAGE_FLAGS --coverage -fprofile-arcs -ftest-coverage -O0 -g)
endif()

# ─────────────────────────────────────────────────────────────────────────────
# Core library — platform-agnostic, no OS / hardware dependency
# ─────────────────────────────────────────────────────────────────────────────
add_library(zzta_core STATIC
    src/CryptoPlatformInterface.cpp
    src/SpdmProtocolEngine.cpp
    src/TokenLifecycleManager.cpp
    src/SomeIpAdaptor.cpp
)

target_include_directories(zzta_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_compile_options(zzta_core PRIVATE ${ZZTA_WARN_FLAGS} ${ZZTA_COVERAGE_FLAGS})

if(ZZTA_COVERAGE_FLAGS)
    target_link_options(zzta_core PUBLIC --coverage)
endif()

if(ZZTA_PRODUCTION_BUILD)
    target_compile_definitions(zzta_core PUBLIC ZZTA_PRODUCTION_BUILD)
endif()

if(ZZTA_ENABLE_ASAN)
    target_compile_options(zzta_core PUBLIC -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(zzta_core    PUBLIC -fsanitize=address)
endif()

if(ZZTA_ENABLE_UBSAN)
    target_compile_options(zzta_core PUBLIC -fsanitize=undefined)
    target_link_options(zzta_core    PUBLIC -fsanitize=undefined)
endif()

# ─────────────────────────────────────────────────────────────────────────────
# Unit test executable (GoogleTest)
# ─────────────────────────────────────────────────────────────────────────────
if(ZZTA_BUILD_TESTS AND NOT CMAKE_CROSSCOMPILING)
    include(FetchContent)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        # Pinned by COMMIT HASH, not tag (ISO/IEC 18974 §3.3 / NIST CSF ID.SC):
        # tags are mutable references and can be force-moved; a commit hash is
        # content-addressed and immutable. This hash corresponds to release
        # v1.14.0. Update the SBOM (sbom/) whenever this pin changes.
        GIT_TAG        f8d7d77c06936315286eb55f8de22cd23c188571  # v1.14.0
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    set(BUILD_GMOCK             OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    add_executable(zzta_tests tests/test_zzta_core.cpp)
    target_link_libraries(zzta_tests PRIVATE zzta_core GTest::gtest)
    target_compile_options(zzta_tests PRIVATE ${ZZTA_WARN_FLAGS} ${ZZTA_COVERAGE_FLAGS})
    if(ZZTA_COVERAGE_FLAGS)
        target_link_options(zzta_tests PUBLIC --coverage)
    endif()

    include(GoogleTest)
    gtest_discover_tests(zzta_tests PROPERTIES TIMEOUT 30)
    enable_testing()
endif()

# ─────────────────────────────────────────────────────────────────────────────
# lcov / genhtml MC/DC coverage report  (`cmake --build . --target coverage`)
# Requires: lcov >= 1.14, genhtml
# Produces: coverage/index.html  (open in browser)
# ─────────────────────────────────────────────────────────────────────────────
if(ZZTA_ENABLE_COVERAGE AND NOT CMAKE_CROSSCOMPILING)
    find_program(LCOV_TOOL    lcov)
    find_program(GENHTML_TOOL genhtml)

    if(LCOV_TOOL AND GENHTML_TOOL)
        add_custom_target(coverage
            COMMAND ${CMAKE_COMMAND} -E make_directory coverage
            # Baseline coverage (zero-counters)
            COMMAND ${LCOV_TOOL}
                --zerocounters
                --directory .
            # Run tests to populate counters
            COMMAND $<TARGET_FILE:zzta_tests>
            # Capture coverage data
            COMMAND ${LCOV_TOOL}
                --capture
                --directory .
                --output-file coverage/coverage.info
                --no-external
            # Filter out test file and gtest internals — production src only
            COMMAND ${LCOV_TOOL}
                --remove coverage/coverage.info
                    "*/tests/*"
                    "*/googletest*"
                    "*/usr/*"
                --output-file coverage/coverage_filtered.info
            # Generate HTML report
            COMMAND ${GENHTML_TOOL}
                coverage/coverage_filtered.info
                --output-directory coverage/
                --title "zzta MC/DC Coverage Report v${PROJECT_VERSION}"
                --legend
                --branch-coverage
                --num-spaces 4
            COMMAND ${CMAKE_COMMAND} -E echo
                "Coverage report: ${CMAKE_BINARY_DIR}/coverage/index.html"
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            COMMENT "Generating MC/DC coverage report with lcov + genhtml"
            DEPENDS zzta_tests
        )
        message(STATUS "Coverage target enabled — run: cmake --build . --target coverage")
    else()
        message(WARNING "lcov/genhtml not found; coverage target unavailable.")
    endif()
endif()

# ─────────────────────────────────────────────────────────────────────────────
# cppcheck static analysis target  (`cmake --build . --target cppcheck`)
# ─────────────────────────────────────────────────────────────────────────────
find_program(CPPCHECK_TOOL cppcheck)
if(CPPCHECK_TOOL)
    add_custom_target(cppcheck
        COMMAND ${CPPCHECK_TOOL}
            --enable=all
            --std=c++14
            --language=c++
            --platform=arm32-wchar_t2
            --suppress=missingIncludeSystem
            --suppress=unusedFunction
            --error-exitcode=1
            --inline-suppr
            -I ${CMAKE_SOURCE_DIR}/include
            ${CMAKE_SOURCE_DIR}/src/
            ${CMAKE_SOURCE_DIR}/include/
        COMMENT "Running cppcheck AUTOSAR static analysis"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )
endif()

# ─────────────────────────────────────────────────────────────────────────────
# AUTOSAR compliance pattern scan  (`cmake --build . --target compliance`)
# ─────────────────────────────────────────────────────────────────────────────
# NOTE: The previous inline `compliance` custom target embedded a `bash -c`
# script containing literal `$(...)` and `$VAR` references. CMake's Ninja
# generator wrote those unescaped `$` characters straight into build.ninja,
# which made Ninja fail to PARSE the file ("bad $-escape"). That aborted the
# entire Ninja build before any target could be compiled, so every Ninja-based
# CI job (build, cross-compile, clang-tidy, coverage, stack-analysis) failed
# regardless of its own logic.
#
# The AUTOSAR forbidden-pattern scan already runs as a dedicated CI job
# (.github/workflows/ci.yml -> "AUTOSAR C++14 Compliance"), so this redundant
# cmake target has been removed. To run the scan locally, invoke the same
# logic from a standalone script rather than an inline cmake COMMAND.

# ─────────────────────────────────────────────────────────────────────────────
# Install rules + CMake package config
# ─────────────────────────────────────────────────────────────────────────────
include(CMakePackageConfigHelpers)

install(TARGETS zzta_core
    EXPORT  zzta-targets
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)
install(DIRECTORY include/zzta DESTINATION include)
install(EXPORT zzta-targets
    NAMESPACE   zzta::
    DESTINATION lib/cmake/zzta
)
install(FILES cmake/zzta-config.cmake
    DESTINATION lib/cmake/zzta
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/zzta-config-version.cmake"
    VERSION       ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/zzta-config-version.cmake"
    DESTINATION lib/cmake/zzta
)

# ─────────────────────────────────────────────────────────────────────────────
# Print summary
# ─────────────────────────────────────────────────────────────────────────────
message(STATUS "")
message(STATUS "=== zonal-zero-trust-authenticator v${PROJECT_VERSION} ===")
message(STATUS "  C++ Standard  : C++${CMAKE_CXX_STANDARD}")
message(STATUS "  Build tests   : ${ZZTA_BUILD_TESTS}")
message(STATUS "  Production    : ${ZZTA_PRODUCTION_BUILD}")
message(STATUS "  ASan          : ${ZZTA_ENABLE_ASAN}")
message(STATUS "  UBSan         : ${ZZTA_ENABLE_UBSAN}")
message(STATUS "  Coverage      : ${ZZTA_ENABLE_COVERAGE}")
message(STATUS "  clang-tidy    : ${ZZTA_ENABLE_CLANG_TIDY}")
message(STATUS "  Compiler      : ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "")
