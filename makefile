# Compiler
CXX = g++

# Directories
SRC_DIR = src
INC_DIR = include
BIN_DIR = bin

# Output executable
TARGET = $(BIN_DIR)/Scaner

# Source and object files
SRCS = $(wildcard $(SRC_DIR)/*.cpp)
OBJS = $(SRCS:$(SRC_DIR)/%.cpp=$(BIN_DIR)/%.o)

# Compiler flags
CXXFLAGS = -I$(INC_DIR) -Wall -std=c++11

# Rule to build the target executable
$(TARGET): $(OBJS)
	$(CXX) $(OBJS) -o $(TARGET)

# Rule to build object files
$(BIN_DIR)/%.o: $(SRC_DIR)/%.cpp | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Rule to create the bin directory if it doesn't exist
$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Clean up build files
.PHONY: clean
clean:
	rm -rf $(BIN_DIR)/*.o $(TARGET)
