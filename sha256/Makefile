# Makefile

# 编译器
CC = gcc

# 编译选项
CFLAGS = -Wall -Wextra -O2

# 源文件列表
SRCS = main.c aes.c sha256.c ripemd160.c compound_hash.c

# 头文件目录（如果头文件在其他文件夹可以加 -Iinclude）
INCLUDES =

# 目标文件列表（.o）
OBJS = $(SRCS:.c=.o)

# 最终生成的可执行文件名
TARGET = program

# 默认目标
all: $(TARGET)

# 链接目标
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

# 生成 .o 文件
%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# 运行程序
run: all
	./$(TARGET)

# 清理编译生成的文件
clean:
	rm -f $(OBJS) $(TARGET)

# 伪目标（不生成与文件同名的目标）
.PHONY: all clean run
