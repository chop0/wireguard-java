cmake_minimum_required(VERSION 3.10)
project(posix_raw_project)

set(CMAKE_C_STANDARD 99)

set(JAVA_AWT_LIBRARY NotNeeded)
set(JAVA_JVM_LIBRARY NotNeeded)
find_package(JNI REQUIRED)
if(JNI_FOUND)
  message(STATUS "JNI include directories: ${JNI_INCLUDE_DIRS}")
else()
  message(FATAL_ERROR "Could not find JNI")
endif()

include_directories(${JNI_INCLUDE_DIRS})

set(SOURCE_FILES
    ax.xz.raw.posix/src/main/c/posix_raw.c
    ax.xz.raw.posix/src/main/c/providers.c
)

add_library(posix_raw SHARED ${SOURCE_FILES})

set(SOURCE_FILES ax.xz.wireguard.noise/src/main/c/poly1305-donna.c)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Ofast -march=native")
add_library(poly1305-donna SHARED ${SOURCE_FILES})