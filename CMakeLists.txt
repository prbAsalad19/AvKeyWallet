cmake_minimum_required(VERSION 3.16)
project(avKeyWallet VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Imposta la configurazione di default su Release se non e' specificata
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Dichiarazione dell'eseguibile dalla cartella src/
add_executable(avKeyWallet src/main.cpp)

# Gestione delle dipendenze per Piattaforma
if(WIN32)
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(SODIUM_PORT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/libsodium-win64")
    else()
        set(SODIUM_PORT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/libsodium-win32")
    endif()

    target_include_directories(avKeyWallet PRIVATE "${SODIUM_PORT_DIR}/include")
    target_link_directories(avKeyWallet PRIVATE "${SODIUM_PORT_DIR}/lib")
    target_link_libraries(avKeyWallet PRIVATE libsodium ws2_32 advapi32)

else()
    find_package(libsodium CONFIG QUIET)

    if(TARGET libsodium::libsodium)
        target_link_libraries(avKeyWallet PRIVATE libsodium::libsodium)
    else()
        find_package(PkgConfig QUIET)
        if(PkgConfig_FOUND)
            pkg_check_modules(SODIUM REQUIRED libsodium)
            target_include_directories(avKeyWallet PRIVATE ${SODIUM_INCLUDE_DIRS})
            target_link_libraries(avKeyWallet PRIVATE ${SODIUM_LIBRARIES})
        else()
            find_library(SODIUM_LIBRARY NAMES sodium libsodium REQUIRED)
            find_path(SODIUM_INCLUDE_DIR NAMES sodium.h REQUIRED)
            target_include_directories(avKeyWallet PRIVATE ${SODIUM_INCLUDE_DIR})
            target_link_libraries(avKeyWallet PRIVATE ${SODIUM_LIBRARY})
        endif()
    endif()
endif()

# ==============================================================================
# OTTIMIZZAZIONI DI MASSIMA E STRIPPING DEI SIMBOLI
# ==============================================================================

# Abilita LTO (Link Time Optimization / Interprocedural Optimization)
include(CheckIPOSupported)
check_ipo_supported(RESULT ipo_supported OUTPUT ipo_error)
if(ipo_supported)
    set_property(TARGET avKeyWallet PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()

# Flag di compilazione e Linker per GCC / Clang / MSVC
if(MSVC)
    # MSVC: Ottimizzazione massima per velocita' (/O2), elimazione codice morto (/Gy, /Gw), stripping simboli (/RELEASE)
    target_compile_options(avKeyWallet PRIVATE $<$<CONFIG:Release>:/O2 /Gy /Gw>)
    target_link_options(avKeyWallet PRIVATE $<$<CONFIG:Release>:/OPT:REF /OPT:ICF /RELEASE>)
else()
    # GCC / Clang:
    # -O3: Massima ottimizzazione delle prestazioni
    # -fdata-sections -ffunction-sections: Separa funzioni e dati per eliminare quelli non usati
    # -s / -Wl,--gc-sections: Rimuove la tabella dei simboli (stripping) e il codice morto
    target_compile_options(avKeyWallet PRIVATE $<$<CONFIG:Release>:-O3 -fdata-sections -ffunction-sections>)
    
    if(APPLE)
        target_link_options(avKeyWallet PRIVATE $<$<CONFIG:Release>:-Wl,-dead_strip>)
    else()
        target_link_options(avKeyWallet PRIVATE $<$<CONFIG:Release>:-s -Wl,--gc-sections>)
    endif()
endif()