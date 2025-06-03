cmake_minimum_required(VERSION 3.10)
project(rhtop_agent)

# C++ Standard setzen
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Ausführbare Datei "agent" aus api.cpp erzeugen
add_executable(agent
    api.cpp
)

# Include-Pfade für Header-Dateien (httplib, json)
target_include_directories(agent PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
