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
include garbled_circuit/CMakeFiles/eval_TinyGarble.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include garbled_circuit/CMakeFiles/eval_TinyGarble.dir/compiler_depend.make

# Include the progress variables for this target.
include garbled_circuit/CMakeFiles/eval_TinyGarble.dir/progress.make

# Include the compile flags for this target's objects.
include garbled_circuit/CMakeFiles/eval_TinyGarble.dir/flags.make

garbled_circuit/CMakeFiles/eval_TinyGarble.dir/codegen:
.PHONY : garbled_circuit/CMakeFiles/eval_TinyGarble.dir/codegen

garbled_circuit/CMakeFiles/eval_TinyGarble.dir/eval_garbled_circuit.cpp.o: garbled_circuit/CMakeFiles/eval_TinyGarble.dir/flags.make
garbled_circuit/CMakeFiles/eval_TinyGarble.dir/eval_garbled_circuit.cpp.o: /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/garbled_circuit/eval_garbled_circuit.cpp
garbled_circuit/CMakeFiles/eval_TinyGarble.dir/eval_garbled_circuit.cpp.o: garbled_circuit/CMakeFiles/eval_TinyGarble.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object garbled_circuit/CMakeFiles/eval_TinyGarble.dir/eval_garbled_circuit.cpp.o"
	cd /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/garbled_circuit && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT garbled_circuit/CMakeFiles/eval_TinyGarble.dir/eval_garbled_circuit.cpp.o -MF CMakeFiles/eval_TinyGarble.dir/eval_garbled_circuit.cpp.o.d -o CMakeFiles/eval_TinyGarble.dir/eval_garbled_circuit.cpp.o -c /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/garbled_circuit/eval_garbled_circuit.cpp

garbled_circuit/CMakeFiles/eval_TinyGarble.dir/eval_garbled_circuit.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/eval_TinyGarble.dir/eval_garbled_circuit.cpp.i"
	cd /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/garbled_circuit && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/garbled_circuit/eval_garbled_circuit.cpp > CMakeFiles/eval_TinyGarble.dir/eval_garbled_circuit.cpp.i

garbled_circuit/CMakeFiles/eval_TinyGarble.dir/eval_garbled_circuit.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/eval_TinyGarble.dir/eval_garbled_circuit.cpp.s"
	cd /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/garbled_circuit && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/garbled_circuit/eval_garbled_circuit.cpp -o CMakeFiles/eval_TinyGarble.dir/eval_garbled_circuit.cpp.s

# Object files for target eval_TinyGarble
eval_TinyGarble_OBJECTS = \
"CMakeFiles/eval_TinyGarble.dir/eval_garbled_circuit.cpp.o"

# External object files for target eval_TinyGarble
eval_TinyGarble_EXTERNAL_OBJECTS =

garbled_circuit/eval_TinyGarble: garbled_circuit/CMakeFiles/eval_TinyGarble.dir/eval_garbled_circuit.cpp.o
garbled_circuit/eval_TinyGarble: garbled_circuit/CMakeFiles/eval_TinyGarble.dir/build.make
garbled_circuit/eval_TinyGarble: /opt/homebrew/lib/libboost_program_options.dylib
garbled_circuit/eval_TinyGarble: garbled_circuit/CMakeFiles/eval_TinyGarble.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable eval_TinyGarble"
	cd /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/garbled_circuit && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/eval_TinyGarble.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
garbled_circuit/CMakeFiles/eval_TinyGarble.dir/build: garbled_circuit/eval_TinyGarble
.PHONY : garbled_circuit/CMakeFiles/eval_TinyGarble.dir/build

garbled_circuit/CMakeFiles/eval_TinyGarble.dir/clean:
	cd /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/garbled_circuit && $(CMAKE_COMMAND) -P CMakeFiles/eval_TinyGarble.dir/cmake_clean.cmake
.PHONY : garbled_circuit/CMakeFiles/eval_TinyGarble.dir/clean

garbled_circuit/CMakeFiles/eval_TinyGarble.dir/depend:
	cd /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/garbled_circuit /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/garbled_circuit /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/garbled_circuit/CMakeFiles/eval_TinyGarble.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : garbled_circuit/CMakeFiles/eval_TinyGarble.dir/depend

