cmake_minimum_required(VERSION 3.10)
project(udptracker)

set(SOURCES
    udptracker.c
)

add_executable(udptracker ${SOURCES})