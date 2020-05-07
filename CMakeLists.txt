cmake_minimum_required(VERSION 3.15)
project(cencrypt C)

set(CMAKE_C_STANDARD 99)
include_directories("C:\\cygwin64\\usr\\include")
include_directories("C:\\Python38\\include")
link_libraries("crypto")
add_executable(cencrypt RSAEncrypt.h RSAEncrypt.c base64.c base64.h main.c)