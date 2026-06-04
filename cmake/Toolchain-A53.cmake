# cmake/Toolchain-A53.cmake
# norxs Technology LLC — zonal-zero-trust-authenticator
# Cross-compilation toolchain for ARM Cortex-A53 (AArch64) / QNX or Linux
# (c) 2026 norxs Technology LLC. All rights reserved.

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

set(TOOLCHAIN_PREFIX aarch64-linux-gnu)

find_program(CMAKE_C_COMPILER   ${TOOLCHAIN_PREFIX}-gcc)
find_program(CMAKE_CXX_COMPILER ${TOOLCHAIN_PREFIX}-g++)
find_program(CMAKE_AR           ${TOOLCHAIN_PREFIX}-ar)
find_program(CMAKE_RANLIB       ${TOOLCHAIN_PREFIX}-ranlib)
find_program(CMAKE_STRIP        ${TOOLCHAIN_PREFIX}-strip)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

# AUTOSAR C++14 compliant flags for Cortex-A53 (AArch64 / ARMv8-A).
# NOTE: -mfpu and -mfloat-abi are AArch32-only options and are rejected by the
# 64-bit aarch64-linux-gnu compiler. On AArch64 the FPU/SIMD (NEON) is mandated
# by the architecture and selected via -mcpu / -march, so no -mfpu is needed.
set(CMAKE_CXX_FLAGS_INIT
    "-mcpu=cortex-a53 \
     -fno-exceptions -fno-rtti -fno-threadsafe-statics \
     -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
     -Os -ffunction-sections -fdata-sections"
)
