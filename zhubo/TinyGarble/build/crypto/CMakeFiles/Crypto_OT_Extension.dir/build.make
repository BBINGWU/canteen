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
include crypto/CMakeFiles/Crypto_OT_Extension.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include crypto/CMakeFiles/Crypto_OT_Extension.dir/compiler_depend.make

# Include the progress variables for this target.
include crypto/CMakeFiles/Crypto_OT_Extension.dir/progress.make

# Include the compile flags for this target's objects.
include crypto/CMakeFiles/Crypto_OT_Extension.dir/flags.make

crypto/CMakeFiles/Crypto_OT_Extension.dir/codegen:
.PHONY : crypto/CMakeFiles/Crypto_OT_Extension.dir/codegen

crypto/CMakeFiles/Crypto_OT_Extension.dir/OT_extension.cpp.o: crypto/CMakeFiles/Crypto_OT_Extension.dir/flags.make
crypto/CMakeFiles/Crypto_OT_Extension.dir/OT_extension.cpp.o: /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/crypto/OT_extension.cpp
crypto/CMakeFiles/Crypto_OT_Extension.dir/OT_extension.cpp.o: crypto/CMakeFiles/Crypto_OT_Extension.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object crypto/CMakeFiles/Crypto_OT_Extension.dir/OT_extension.cpp.o"
	cd /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/crypto && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT crypto/CMakeFiles/Crypto_OT_Extension.dir/OT_extension.cpp.o -MF CMakeFiles/Crypto_OT_Extension.dir/OT_extension.cpp.o.d -o CMakeFiles/Crypto_OT_Extension.dir/OT_extension.cpp.o -c /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/crypto/OT_extension.cpp

crypto/CMakeFiles/Crypto_OT_Extension.dir/OT_extension.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/Crypto_OT_Extension.dir/OT_extension.cpp.i"
	cd /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/crypto && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/crypto/OT_extension.cpp > CMakeFiles/Crypto_OT_Extension.dir/OT_extension.cpp.i

crypto/CMakeFiles/Crypto_OT_Extension.dir/OT_extension.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/Crypto_OT_Extension.dir/OT_extension.cpp.s"
	cd /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/crypto && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/crypto/OT_extension.cpp -o CMakeFiles/Crypto_OT_Extension.dir/OT_extension.cpp.s

Crypto_OT_Extension: crypto/CMakeFiles/Crypto_OT_Extension.dir/OT_extension.cpp.o
Crypto_OT_Extension: crypto/CMakeFiles/Crypto_OT_Extension.dir/build.make
.PHONY : Crypto_OT_Extension

# Rule to build all files generated by this target.
crypto/CMakeFiles/Crypto_OT_Extension.dir/build: Crypto_OT_Extension
.PHONY : crypto/CMakeFiles/Crypto_OT_Extension.dir/build

crypto/CMakeFiles/Crypto_OT_Extension.dir/clean:
	cd /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/crypto && $(CMAKE_COMMAND) -P CMakeFiles/Crypto_OT_Extension.dir/cmake_clean.cmake
.PHONY : crypto/CMakeFiles/Crypto_OT_Extension.dir/clean

crypto/CMakeFiles/Crypto_OT_Extension.dir/depend:
	cd /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/crypto /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/crypto /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/crypto/CMakeFiles/Crypto_OT_Extension.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : crypto/CMakeFiles/Crypto_OT_Extension.dir/depend

