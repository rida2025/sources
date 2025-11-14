
cmake_minimum_required(VERSION 3.24)
project(rida)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Use lowercase for gflags - this is often the issue
find_package(gflags REQUIRED)

# Create an alias so glog and remill can find gflags::gflags
if(NOT TARGET gflags::gflags)
    add_library(gflags::gflags ALIAS gflags_nothreads_static)
endif()

find_package(glog REQUIRED)
find_package(remill REQUIRED)

add_executable(${PROJECT_NAME} main.cpp)

target_link_libraries(${PROJECT_NAME} PRIVATE 
    glog::glog 
    gflags::gflags
    remill
)
