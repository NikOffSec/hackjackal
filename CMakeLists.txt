cmake_minimum_required(VERSION 4.3)

project(hackjackal VERSION 0.1 DESCRIPTION "Project 2 for COP3530" LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(imgui
  GIT_REPOSITORY https://github.com/ocornut/imgui.git
  GIT_TAG v1.92.8)
FetchContent_Declare(Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG v3.16.0)
FetchContent_MakeAvailable(imgui Catch2)

find_package(glfw3 REQUIRED)
find_package(OpenGL REQUIRED)

add_library(imgui STATIC
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp
    ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    ${imgui_SOURCE_DIR}/imgui_demo.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_glfw.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp)
target_include_directories(imgui PUBLIC ${imgui_SOURCE_DIR} ${imgui_SOURCE_DIR}/backends)
target_link_libraries(imgui PUBLIC glfw OpenGL::GL)

add_library(core util.cpp parser.cpp)
target_include_directories(core PUBLIC include)

set_target_properties(app PROPERTIES OUTPUT_NAME hackjackal)
add_executable(app main.cpp)
target_link_libraries(app PRIVATE core imgui)

enable_testing()
add_executable(tests tests/tests.cpp)
target_link_libraries(tests PRIVATE core Catch2::Catch2WithMain)
list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
include(Catch)
catch_discover_tests(tests)

