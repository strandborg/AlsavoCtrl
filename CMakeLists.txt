cmake_minimum_required(VERSION 3.10)

project(AlsavoCtrl)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_executable(AlsavoCtrl AlsavoCtrl.cpp MD5.cpp loguru.cpp)

IF(UNIX)
    target_link_libraries(AlsavoCtrl pthread atomic)
ENDIF(UNIX)

