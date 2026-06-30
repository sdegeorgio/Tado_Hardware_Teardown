# CMakeLists.txt
#
# Tado 868 MHz Wireshark dissector plugin
#
# Builds as part of the Wireshark in-tree build.  Register this directory
# via CMakeListsCustom.txt in the Wireshark source root — see README.md.
#
# SPDX-License-Identifier: GPL-2.0-or-later

include(WiresharkPlugin)

# Plugin name and version info (major minor micro extra)
set_module_info(tado 1 0 0 0)

set(DISSECTOR_SRC
    packet-tirpi.c
    packet-tado.c
)

set(PLUGIN_FILES
    plugin.c
    ${DISSECTOR_SRC}
)

set_source_files_properties(
    ${PLUGIN_FILES}
    PROPERTIES
    COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

register_plugin_files(plugin.c
    plugin
    ${DISSECTOR_SRC}
)

add_plugin_library(tado-dissector epan)
target_link_libraries(tado-dissector epan)
install_plugin(tado-dissector epan)

file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
CHECKAPI(
    NAME
      tado
    SWITCHES
      -g abort -g termoutput -build
    SOURCES
      ${DISSECTOR_SRC}
      ${DISSECTOR_HEADERS}
)
