cmake_minimum_required(VERSION 3.15)
cmake_policy(SET CMP0091 NEW)
cmake_policy(SET CMP0042 NEW)

project (wg)

add_compile_definitions(NAPI_VERSION=8 NAPI_CPP_EXCEPTIONS)
set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 17)

execute_process(COMMAND node -p "require('node-addon-api').include"
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE NODE_ADDON_API_DIR
)
string(REPLACE "\n" "" NODE_ADDON_API_DIR ${NODE_ADDON_API_DIR})
string(REPLACE "\"" "" NODE_ADDON_API_DIR ${NODE_ADDON_API_DIR})
include_directories(PRIVATE ${NODE_ADDON_API_DIR})
include_directories(${CMAKE_JS_INC})
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/addon")
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/addon/genKey")

if(UNIX)
  add_definitions(-fpermissive -fexceptions -w -fpermissive -fPIC)
endif()

file(GLOB SOURCE_FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/addon/main.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/addon/genKey/wgkeys.cpp"
)

if(MSVC)
  file(GLOB SOURCE_FILES ${SOURCE_FILES} "${CMAKE_CURRENT_SOURCE_DIR}/addon/win/wginterface.cpp")
  include_directories("${CMAKE_CURRENT_SOURCE_DIR}/addon/win")
  add_compile_definitions(_HAS_EXCEPTIONS=1 ONSTARTADDON)
  target_link_libraries(${PROJECT_NAME}
    "wbemuuid.lib"
    "bcrypt.lib"
    "crypt32.lib"
    "iphlpapi.lib"
    "kernel32.lib"
    "ntdll.lib"
    "ws2_32.lib"
    "setupapi.lib"
  )
elseif(UNIX AND NOT APPLE OR ANDROID)
  include_directories("${CMAKE_CURRENT_SOURCE_DIR}/addon/linux")
  file(GLOB SOURCE_FILES ${SOURCE_FILES}
    "${CMAKE_CURRENT_SOURCE_DIR}/addon/linux/wireguard.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/addon/linux/wginterface.cpp"
  )
else()
  message(STATUS "Buiding go Userspace")
  if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/addon/userspace/wg-go.o)
    file(REMOVE_RECURSE ${CMAKE_CURRENT_SOURCE_DIR}/addon/userspace/wg-go.o)
  endif()
  if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/addon/userspace/wg-go.h)
    file(REMOVE_RECURSE ${CMAKE_CURRENT_SOURCE_DIR}/addon/userspace/wg-go.h)
  endif()
  set(ENV{CGO_ENABLED} 1)
  set(ENV{LDFLAGS} -w)
  # Remove CXX and CC envs to CGO
  set(ENV{DCXX} ENV{CXX})
  set(ENV{DCC} ENV{CC})
  set(ENV{CXX})
  set(ENV{CC})
  execute_process(
    COMMAND go build -trimpath -v -o ../wg-go.o -buildmode c-archive .
    # COMMAND env
    RESULT_VARIABLE GOCODE
    OUTPUT_VARIABLE GOBUILDLOG
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/addon/userspace/go
  )
  set(ENV{CXX} ENV{DCXX})
  set(ENV{CC} ENV{DCC})
  if(NOT GOCODE EQUAL "0")
    message(FATAL_ERROR "cannot build go userspace code exit ${GOCODE}\n${GOBUILDLOG}")
  endif()
  include_directories("${CMAKE_CURRENT_SOURCE_DIR}/addon/userspace")
  set(USERSPACEOBJ ${CMAKE_CURRENT_SOURCE_DIR}/addon/userspace/wg-go.o)
  file(GLOB SOURCE_FILES ${SOURCE_FILES} "${CMAKE_CURRENT_SOURCE_DIR}/addon/userspace/wginterface.cpp")
endif()

add_library(${PROJECT_NAME} SHARED ${SOURCE_FILES} ${CMAKE_JS_SRC})
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "" SUFFIX ".node")
target_link_libraries(${PROJECT_NAME} ${USERSPACEOBJ} ${CMAKE_JS_LIB})

if(MSVC AND CMAKE_JS_NODELIB_DEF AND CMAKE_JS_NODELIB_TARGET)
  # Generate node.lib
  execute_process(COMMAND ${CMAKE_AR} /def:${CMAKE_JS_NODELIB_DEF} /out:${CMAKE_JS_NODELIB_TARGET} ${CMAKE_STATIC_LINKER_FLAGS})
endif()
