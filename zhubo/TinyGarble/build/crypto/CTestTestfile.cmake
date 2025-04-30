# CMake generated Testfile for 
# Source directory: /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/crypto
# Build directory: /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/crypto
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(Crypto_BN_Test "BN_Test" "--log2std")
set_tests_properties(Crypto_BN_Test PROPERTIES  FAIL_REGULAR_EXPRESSION "[^a-z]Failed;failed" _BACKTRACE_TRIPLES "/Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/crypto/CMakeLists.txt;24;add_test;/Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/crypto/CMakeLists.txt;0;")
add_test(Crypto_OT_Test "OT_Test" "--log2std")
set_tests_properties(Crypto_OT_Test PROPERTIES  FAIL_REGULAR_EXPRESSION "[^a-z]Failed;failed" _BACKTRACE_TRIPLES "/Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/crypto/CMakeLists.txt;47;add_test;/Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/crypto/CMakeLists.txt;0;")
add_test(Crypto_OT_Extension_Test "OT_Extension_Test" "--log2std")
set_tests_properties(Crypto_OT_Extension_Test PROPERTIES  FAIL_REGULAR_EXPRESSION "[^a-z]Failed;failed" _BACKTRACE_TRIPLES "/Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/crypto/CMakeLists.txt;71;add_test;/Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/crypto/CMakeLists.txt;0;")
