# Compile the exact production library source list and configuration.
get_filename_component(REPO "${CMAKE_CURRENT_LIST_DIR}/../../../../../.." ABSOLUTE)
include("${REPO}/firmware/components/quantum_wolfssl/CMakeLists.txt")
