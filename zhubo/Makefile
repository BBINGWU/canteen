CXX = g++
CXXFLAGS = -std=c++11 -O2 -Wall -Wno-deprecated-declarations

# 你的路径
EMP_TOOL_DIR = /Users/bingwu/Downloads/毕业论文/code/zhubo/emp-tool
EMP_SH2PC_DIR = /Users/bingwu/Downloads/毕业论文/code/zhubo/emp-sh2pc
OPENSSL_DIR = /opt/homebrew/opt/openssl@3

INCLUDES = -I$(EMP_TOOL_DIR) -I$(EMP_SH2PC_DIR) -I$(OPENSSL_DIR)/include

LIBS = -L$(OPENSSL_DIR)/lib -lssl -lcrypto

CPPFLAGS = -I$(OPENSSL_DIR)/include
LDFLAGS = -L$(OPENSSL_DIR)/lib

SOURCES = test_ripemd160.cpp ripemd160_emp.cpp
TARGET = test_ripemd160

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CXX) $(CPPFLAGS) $(LDFLAGS) $(CXXFLAGS) $(INCLUDES) $(SOURCES) -o $(TARGET) $(LIBS)

clean:
	rm -f $(TARGET)
