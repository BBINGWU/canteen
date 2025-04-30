# CMake generated Testfile for 
# Source directory: /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/scd
# Build directory: /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/scd
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(SCD_V2SCD_Test "V2SCD_Test" "--error2std")
set_tests_properties(SCD_V2SCD_Test PROPERTIES  FAIL_REGULAR_EXPRESSION "[^a-z]Failed;failed" _BACKTRACE_TRIPLES "/Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/scd/CMakeLists.txt;56;add_test;/Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/scd/CMakeLists.txt;0;")
add_test(SCD_SCD_Evaluator_Test "SCD_Evaluator_Test" "--log2std")
set_tests_properties(SCD_SCD_Evaluator_Test PROPERTIES  FAIL_REGULAR_EXPRESSION "[^a-z]Failed;failed" _BACKTRACE_TRIPLES "/Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/scd/CMakeLists.txt;79;add_test;/Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/scd/CMakeLists.txt;0;")
