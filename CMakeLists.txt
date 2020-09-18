cmake_minimum_required(VERSION 3.0.0)
project(KeePassPinentry VERSION 0.1.0 LANGUAGES CXX)
set(${CMAKE_CXX_STANDARD} 17)

include(CTest)
enable_testing()

find_package(Boost 1.64.0 REQUIRED
    REQUIRED COMPONENTS filesystem)
find_package(Threads REQUIRED)

aux_source_directory(src KEEPASS_PINENTRY_SOURCE)
add_executable(KeePassPinentry ${KEEPASS_PINENTRY_SOURCE})
target_include_directories(KeePassPinentry
    PRIVATE ${Boost_INCLUDE_DIRS} include)
target_link_libraries(KeePassPinentry ${Boost_LIBRARIES} Threads::Threads)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
