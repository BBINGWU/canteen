# CMake generated Testfile for 
# Source directory: /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/tcpip
# Build directory: /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/tcpip
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(TCPIP_TCPIP_Test "TCPIP_Test" "--log2std")
set_tests_properties(TCPIP_TCPIP_Test PROPERTIES  FAIL_REGULAR_EXPRESSION "[^a-z]Failed;failed" _BACKTRACE_TRIPLES "/Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/tcpip/CMakeLists.txt;17;add_test;/Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/tcpip/CMakeLists.txt;0;")
