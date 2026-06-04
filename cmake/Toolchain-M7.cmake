# cmake/Toolchain-M7.cmake
# norxs Technology LLC — zonal-zero-trust-authenticator
# Cross-compilation toolchain for ARM Cortex-M7 bare-metal (arm-none-eabi)
# (c) 2026 norxs Technology LLC. All rights reserved.

set(CMAKE_SYSTEM_NAME  Generic)
set(CMAKE_SYSTEM_PROCESSOR arm)

set(TOOLCHAIN_PREFIX arm-none-eabi)

find_program(CMAKE_C_COMPILER   ${TOOLCHAIN_PREFIX}-gcc)
find_program(CMAKE_CXX_COMPILER ${TOOLCHAIN_PREFIX}-g++)
find_program(CMAKE_AR           ${TOOLCHAIN_PREFIX}-ar)
find_program(CMAKE_RANLIB       ${TOOLCHAIN_PREFIX}-ranlib)
find_program(CMAKE_OBJCOPY      ${TOOLCHAIN_PREFIX}-objcopy)
find_program(CMAKE_SIZE         ${TOOLCHAIN_PREFIX}-size)

set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

# AUTOSAR C++14 compliant flags for Cortex-M7 with FPU
# -fno-exceptions and -fno-rtti are mandatory for AUTOSAR C++14 compliance
set(CMAKE_CXX_FLAGS_INIT
    "-mcpu=cortex-m7 -mfpu=fpv5-d16 -mfloat-abi=hard -mthumb \
     -fno-exceptions -fno-rtti -fno-threadsafe-statics \
     -fno-use-cxa-atexit -fno-common \
     -Os -ffunction-sections -fdata-sections \
     -fstack-usage \
     --specs=nosys.specs --specs=nano.specs"
)

set(CMAKE_EXE_LINKER_FLAGS_INIT
    "-Wl,--gc-sections -Wl,--print-memory-usage --specs=nosys.specs"
)
