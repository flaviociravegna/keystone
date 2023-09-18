cmake_minimum_required(VERSION 3.10)
include(ExternalProject)

macro(global_set Name Value)
    #  message("set ${Name} to " ${ARGN})
    set(${Name} "${Value}" CACHE STRING "NoDesc" FORCE)
endmacro()

macro(check_compiler target)
  message(STATUS "Check for working C compiler: ${target}")
  execute_process(
    COMMAND ${target} -print-file-name=crt.o
    OUTPUT_FILE OUTPUT
    RESULT_VARIABLE ERROR)

  if ("${ERROR}" STREQUAL 0)
    message(STATUS "Check for working C compiler: ${target} -- works")
  else()
    message(FATAL_ERROR "Check for working C compiler: ${target} -- not working")
  endif()
endmacro()

macro(subdirs_list OUT_VARIABLE DIRWORK)
  file(GLOB children RELATIVE ${DIRWORK} ${DIRWORK}/*)
  set(_subdirs    "")
  foreach(child ${children})
    if (IS_DIRECTORY ${DIRWORK}/${child})
      list(APPEND _subdirs  ${child})
    endif()
  endforeach()
  set(${OUT_VARIABLE} ${_subdirs})
endmacro()

macro(add_files FILE_LIST DIRWORK)
  foreach(file ${ARGN})
    list(APPEND ${FILE_LIST} ${DIRWORK}/${file})
  endforeach()
endmacro()

macro(get_runtime_dir var)
  get_filename_component(SRCDIR ${CMAKE_SOURCE_DIR} NAME)
  if(${SRCDIR} STREQUAL "sdk")
    get_filename_component(${var} ../runtime REALPATH BASE_DIR "${CMAKE_SOURCE_DIR}")
  elseif(${SRCDIR} STREQUAL "keystone")
    get_filename_component(${var} ./runtime REALPATH BASE_DIR "${CMAKE_SOURCE_DIR}")
  elseif(${SRCDIR} STREQUAL "keystone-demo")
    get_filename_component(${var} ../keystone/runtime REALPATH BASE_DIR "${CMAKE_SOURCE_DIR}")
  elseif(${SRCDIR} STREQUAL "keystone-CA")
    get_filename_component(${var} ../keystone/runtime REALPATH BASE_DIR "${CMAKE_SOURCE_DIR}")
  elseif(${SRCDIR} STREQUAL "keystone-trusted-channel")
    get_filename_component(${var} ../keystone/runtime REALPATH BASE_DIR "${CMAKE_SOURCE_DIR}")
  if(${SRCDIR} STREQUAL "sdk_std")
    get_filename_component(${var} ../runtime REALPATH BASE_DIR "${CMAKE_SOURCE_DIR}")
  else()
    message(FATAL_ERROR "Don't know how to find runtime from current directory" ${SRCDIR})
  endif()
endmacro()

macro(add_keystone_package target_name package_name package_script) # files are passed via ${ARGN}
  set(pkg_dir ${CMAKE_CURRENT_BINARY_DIR}/pkg)
  add_custom_command(OUTPUT ${pkg_dir} COMMAND mkdir ${pkg_dir})

  message(STATUS " * Configuring Keystone package (${target_name})")
  foreach(dep IN ITEMS ${ARGN})
    get_filename_component(filename ${dep} NAME)
    string(CONCAT pkg_file "${pkg_dir}/" "${filename}")
    list(APPEND pkg_files ${pkg_file})

    message(STATUS "   Adding ${filename}")
    add_custom_command(OUTPUT ${pkg_file} DEPENDS ${dep} ${pkg_dir}
      COMMAND cp ${dep} ${pkg_file})
  endforeach(dep)

  message(STATUS "   Package: ${package_name}")
  message(STATUS "   Script: ${package_script}")

  separate_arguments(package_script_raw UNIX_COMMAND ${package_script})
  add_custom_target(${target_name} DEPENDS ${pkg_files}
    COMMAND
      ${MAKESELF} --noprogress ${pkg_dir} ${package_name} \"Keystone Enclave Package\" ${package_script_raw}
    )

endmacro(add_keystone_package)

macro(use_std_toolchain)
  set(CMAKE_C_COMPILER /usr/bin/gcc)
  set(CMAKE_CXX_COMPILER /usr/bin/g++)
  set(CMAKE_ASM_COMPILER /usr/bin/gcc)
  set(CMAKE_LINKER ld)
  set(CMAKE_AR ar)
  set(CMAKE_OBJCOPY objcopy)
  set(CMAKE_OBJDUMP objdump)
  set(CMAKE_SYSTEM_NAME "Linux")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror")

  global_set(CMAKE_C_COMPILER_WORKS 1)
  global_set(CMAKE_CXX_COMPILER_WORKS 1)
endmacro()

