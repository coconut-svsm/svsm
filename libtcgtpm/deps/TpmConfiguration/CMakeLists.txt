# Microsoft Reference Implementation for TPM 2.0
# Copyright (c) Microsoft Corporation
# This software is being made available under certain license terms, as detailed at
# https://github.com/microsoft/ms-tpm-20-ref/blob/main/LICENSE
#
##########################################################
# DO NOT MODIFY - TPM Configuration Library
##########################################################
# The contents of the source files may be modified to specify any valid
# desired configuraton.  However, the CMake library name "TpmConfiguration"
# is required by the CoreLib to reference this project.  Recommend making
# no changes in this file.
cmake_minimum_required(VERSION 3.16.3)

# set the project name and version
# Must be TpmConfiguration
project(TpmConfiguration VERSION 1.0)
print_project_info()

# use standard output directories.  Expected by package_utilities
include(GNUInstallDirs)

add_library(TpmConfiguration INTERFACE)
add_library(TpmConfiguration::TpmConfiguration ALIAS TpmConfiguration)

target_include_directories(${PROJECT_NAME}
    INTERFACE
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/TpmConfiguration>"
)

# create install and export information for downstream projects to use
install_and_export_config_targets(${PROJECT_NAME})

##############################################################
# BEGIN --- install the header files provided by this project.
##############################################################

install(FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmConfiguration/TpmBuildSwitches.h
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmConfiguration/TpmProfile.h
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmConfiguration/TpmProfile_CommandList.h
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmConfiguration/TpmProfile_Common.h
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmConfiguration/TpmProfile_ErrorCodes.h
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmConfiguration/TpmProfile_Misc.h
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmConfiguration/VendorInfo.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/TpmConfiguration)

# LAST: create the targets.cmake file for this package
export_targets_cmake_file(${PROJECT_NAME})
