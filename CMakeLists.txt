cmake_minimum_required(VERSION 3.16)
project(SecureVaultManager VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Trova la libreria libsodium
find_package(libsodium CONFIG)

if(NOT libsodium_FOUND)
    # Fallback per sistemi Linux/Unix dove libsodium usa pkg-config
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(SODIUM REQUIRED libsodium)
    else()
        find_library(SODIUM_LIBRARY NAMES sodium libsodium REQUIRED)
        find_path(SODIUM_INCLUDE_DIR NAMES sodium.h REQUIRED)
    endif()
endif()

# Definizione dell'eseguibile
add_executable(secure_vault main.cpp)

# Configurazione delle dipendenze e delle include directory
if(TARGET libsodium::libsodium)
    target_link_libraries(secure_vault PRIVATE libsodium::libsodium)
elseif(SODIUM_FOUND)
    target_include_directories(secure_vault PRIVATE ${SODIUM_INCLUDE_DIRS})
    target_link_libraries(secure_vault PRIVATE ${SODIUM_LIBRARIES})
else()
    target_include_directories(secure_vault PRIVATE ${SODIUM_INCLUDE_DIR})
    target_link_libraries(secure_vault PRIVATE ${SODIUM_LIBRARY})
endif()

# Gestione delle librerie specifiche per piattaforma (Windows/POSIX)
if(WIN32)
    # Su Windows, libsodium o le chiamate di sistema potrebbero richiedere ws2_32 o advapi32
    target_link_libraries(secure_vault PRIVATE ws2_32 advapi32)
endif()

# Flags di compilazione consigliati per la sicurezza
if(MSVC)
    target_compile_options(secure_vault PRIVATE /W4 /WX /GX)
else()
    target_compile_options(secure_vault PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()