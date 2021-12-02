cmake_minimum_required(VERSION 3.12.4)

project(fim_db_interface_unit_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage -fsanitize=address,leak,undefined")

file(GLOB DB_INTERFACE_TEST "dbTest.cpp")
file(GLOB DB_INTERFACE_IMP
    "${SRC_FOLDER}/syscheckd/db/src/db.cpp")

include_directories("${SRC_FOLDER}/syscheckd/db/tests")

add_executable(fim_db_interface_unit_test
               ${DB_INTERFACE_TEST}
               ${DB_INTERFACE_IMP})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(fim_db_interface_unit_test
        debug gtestd
        debug gmockd
        debug gtest_maind
        debug gmock_maind
        optimized gtest
        optimized gmock
        optimized gtest_main
        optimized gmock_main
        pthread
        sqlite3
        dbsync
        rsync
        -static-libgcc -static-libstdc++
    )
else()
    target_link_libraries(fim_db_interface_unit_test
        debug gtestd
        debug gmockd
        debug gtest_maind
        debug gmock_maind
        optimized gtest
        optimized gmock
        optimized gtest_main
        optimized gmock_main
        pthread
        rsync
        dbsync
        dl
    )
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_test(NAME fim_db_interface_unit_test
         COMMAND fim_db_interface_unit_test)
