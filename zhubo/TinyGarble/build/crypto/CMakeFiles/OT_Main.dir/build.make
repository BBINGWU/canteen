# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 4.0

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /opt/homebrew/bin/cmake

# The command to remove a file.
RM = /opt/homebrew/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build

# Include any dependencies generated for this target.
include crypto/CMakeFiles/OT_Main.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include crypto/CMakeFiles/OT_Main.dir/compiler_depend.make

# Include the progress variables for this target.
include crypto/CMakeFiles/OT_Main.dir/progress.make

# Include the compile flags for this target's objects.
include crypto/CMakeFiles/OT_Main.dir/flags.make

crypto/CMakeFiles/OT_Main.dir/codegen:
.PHONY : crypto/CMakeFiles/OT_Main.dir/codegen

crypto/CMakeFiles/OT_Main.dir/OT_main.cpp.o: crypto/CMakeFiles/OT_Main.dir/flags.make
crypto/CMakeFiles/OT_Main.dir/OT_main.cpp.o: /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/crypto/OT_main.cpp
crypto/CMakeFiles/OT_Main.dir/OT_main.cpp.o: crypto/CMakeFiles/OT_Main.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object crypto/CMakeFiles/OT_Main.dir/OT_main.cpp.o"
	cd /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/crypto && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT crypto/CMakeFiles/OT_Main.dir/OT_main.cpp.o -MF CMakeFiles/OT_Main.dir/OT_main.cpp.o.d -o CMakeFiles/OT_Main.dir/OT_main.cpp.o -c /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/crypto/OT_main.cpp

crypto/CMakeFiles/OT_Main.dir/OT_main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/OT_Main.dir/OT_main.cpp.i"
	cd /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/crypto && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/crypto/OT_main.cpp > CMakeFiles/OT_Main.dir/OT_main.cpp.i

crypto/CMakeFiles/OT_Main.dir/OT_main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/OT_Main.dir/OT_main.cpp.s"
	cd /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/crypto && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/crypto/OT_main.cpp -o CMakeFiles/OT_Main.dir/OT_main.cpp.s

# Object files for target OT_Main
OT_Main_OBJECTS = \
"CMakeFiles/OT_Main.dir/OT_main.cpp.o"

# External object files for target OT_Main
OT_Main_EXTERNAL_OBJECTS = \
"/Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/crypto/CMakeFiles/Crypto_BN.dir/BN.cpp.o" \
"/Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/crypto/CMakeFiles/Crypto_OT.dir/OT.cpp.o" \
"/Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/crypto/CMakeFiles/Crypto_OT_Extension.dir/OT_extension.cpp.o" \
"/Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/tcpip/CMakeFiles/TCPIP_TCPIP.dir/tcpip.cpp.o" \
"/Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/util/CMakeFiles/Util_Util.dir/util.cpp.o" \
"/Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/util/CMakeFiles/Util_Log.dir/log.cpp.o"

crypto/OT_Main: crypto/CMakeFiles/OT_Main.dir/OT_main.cpp.o
crypto/OT_Main: crypto/CMakeFiles/Crypto_BN.dir/BN.cpp.o
crypto/OT_Main: crypto/CMakeFiles/Crypto_OT.dir/OT.cpp.o
crypto/OT_Main: crypto/CMakeFiles/Crypto_OT_Extension.dir/OT_extension.cpp.o
crypto/OT_Main: tcpip/CMakeFiles/TCPIP_TCPIP.dir/tcpip.cpp.o
crypto/OT_Main: util/CMakeFiles/Util_Util.dir/util.cpp.o
crypto/OT_Main: util/CMakeFiles/Util_Log.dir/log.cpp.o
crypto/OT_Main: crypto/CMakeFiles/OT_Main.dir/build.make
crypto/OT_Main: /opt/homebrew/Cellar/openssl@3/3.5.0/lib/libssl.dylib
crypto/OT_Main: /opt/homebrew/Cellar/openssl@3/3.5.0/lib/libcrypto.dylib
crypto/OT_Main: /opt/homebrew/lib/libboost_program_options.dylib
crypto/OT_Main: crypto/CMakeFiles/OT_Main.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable OT_Main"
	cd /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/crypto && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/OT_Main.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
crypto/CMakeFiles/OT_Main.dir/build: crypto/OT_Main
.PHONY : crypto/CMakeFiles/OT_Main.dir/build

crypto/CMakeFiles/OT_Main.dir/clean:
	cd /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/crypto && $(CMAKE_COMMAND) -P CMakeFiles/OT_Main.dir/cmake_clean.cmake
.PHONY : crypto/CMakeFiles/OT_Main.dir/clean

crypto/CMakeFiles/OT_Main.dir/depend:
	cd /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/crypto /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/crypto /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/crypto/CMakeFiles/OT_Main.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : crypto/CMakeFiles/OT_Main.dir/depend

