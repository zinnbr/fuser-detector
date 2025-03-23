cmake_minimum_required(VERSION 3.16)

project("Fuser detector")

set(CMAKE_C_STANDARD 20)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_options(-O4 -fno-fast-math)
# add_link_options(-static -pthread -lpthread)

file(GLOB_RECURSE SOURCES "Fuser detector/**.cpp" "Fuser detector/**.hpp" "Fuser detector/**.c" "Fuser detector/**.h")

add_executable(${CONFIGURE_TARGET} PUBLIC ${SOURCES})