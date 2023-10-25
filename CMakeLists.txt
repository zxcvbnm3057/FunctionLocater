cmake_minimum_required(VERSION 3.10)

project(FunctionLocater)

set(SOURCES
        jpt.hpp
        FunctionLocater.cpp
        FunctionLocater.hpp
        LengthDisasm/LengthDisasm.c
        LengthDisasm/LengthDisasm.h
)

add_library(FunctionLocater STATIC ${SOURCES})