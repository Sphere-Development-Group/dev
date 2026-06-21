# ================================================
# Mjolnir
# ================================================

# Имя исполняемого файла
TARGET := ./build/main.bin

# Директории
SRC_DIR := src
BUILD_DIR := build
OBJ_DIR := $(BUILD_DIR)/obj

# Исходные файлы
SRCS := main.cpp \
        $(wildcard $(SRC_DIR)/core/*.cpp) \
        $(wildcard $(SRC_DIR)/network/*.cpp) \
        $(wildcard $(SRC_DIR)/proto/*.cpp)

# Объектные файлы
OBJS := $(SRCS:%.cpp=$(OBJ_DIR)/%.o)

# Компилятор
CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O3 -march=native -flto -g

# DPDK через pkg-config
PKG_CONFIG := pkg-config
DPDK_CFLAGS := $(shell $(PKG_CONFIG) --cflags libdpdk)
DPDK_LIBS   := $(shell $(PKG_CONFIG) --libs libdpdk)

# Включаемые директории
INCLUDES := -I. -I$(SRC_DIR) -I$(SRC_DIR)/core -I$(SRC_DIR)/network -I$(SRC_DIR)/proto

# Финальные флаги
ALL_CFLAGS := $(CXXFLAGS) $(INCLUDES) $(DPDK_CFLAGS)
ALL_LIBS   := $(DPDK_LIBS) -lpthread -ldl -lnuma -lprotobuf -lyaml-cpp

# Цвета для вывода
GREEN := \033[0;32m
NC := \033[0m

.PHONY: all clean directories


all: directories $(TARGET)

directories:
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(OBJ_DIR)/src/core
	@mkdir -p $(OBJ_DIR)/src/network
	@mkdir -p $(OBJ_DIR)/src/proto

$(TARGET): $(OBJS)
	@echo "$(GREEN)Linking $@$(NC)"
	$(CXX) $(OBJS) -o $@ $(ALL_LIBS)
	@echo "$(GREEN)Build complete: $@$(NC)"

# Компиляция .cpp -> .o
$(OBJ_DIR)/%.o: %.cpp
	@mkdir -p $(dir $@)
	@echo "$(GREEN)Compiling $<$(NC)"
	$(CXX) $(ALL_CFLAGS) -c $< -o $@


# Пересборка protobuf, если .proto изменился
$(SRC_DIR)/proto/protobuf.pb.cpp $(SRC_DIR)/proto/protobuf.pb.h: $(SRC_DIR)/proto/protobuf.proto
	protoc --cpp_out=$(SRC_DIR)/proto $<


clean:
	rm -rf $(BUILD_DIR)
	@echo "Clean done."

run: all
	$(TARGET)

# Зависимости от заголовочных файлов (можно расширить)
$(OBJ_DIR)/main.o: main.cpp \
    $(SRC_DIR)/core/manager.hpp \
    $(SRC_DIR)/core/lcore_worker.hpp \
    $(SRC_DIR)/network/*.hpp

print-flags:
	@echo "DPDK CFLAGS: $(DPDK_CFLAGS)"
	@echo "DPDK LIBS:   $(DPDK_LIBS)"

help:
	@echo "Available targets:"
	@echo "  all      - build project (default)"
	@echo "  clean    - remove build artifacts"
	@echo "  run      - build and run"
	@echo "  print-flags - show DPDK pkg-config flags"