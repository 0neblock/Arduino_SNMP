BUILD_DIR ?= ./build/build
SRC_DIRS ?= ../src . ../examples

TEST_SRCS := $(shell find $(SRC_DIRS) -name \*.cpp \! -name mock.cpp \! -name CMakeCXXCompilerId.cpp)
TEST_OBJS := $(TEST_SRCS:%=$(BUILD_DIR)/%.o)
TEST_DEPS := $(TEST_OBJS:.o=.d)

MOCK_SRCS := $(shell find $(SRC_DIRS) -name \*.cpp \! -name SNMP_Agent.cpp \! -name tests.cpp \! -name CMakeCXXCompilerId.cpp)
MOCK_OBJS := $(MOCK_SRCS:%=$(BUILD_DIR)/%.o)
MOCK_DEPS := $(MOCK_OBJS:.o=.d)

EXAMPLE_SRCS := $(shell find $(SRC_DIRS) \( -name \*.cpp -o -name ESP32_SNMP.ino \) \! -name mock.cpp \! -name tests.cpp \! -name CMakeCXXCompilerId.cpp)
EXAMPLE_OBJS := $(EXAMPLE_SRCS:%=$(BUILD_DIR)/%.o)

CC = c++
CXX = c++

CPPFLAGS ?= -I"../src" -I"../" -MMD -MP -std=c++11 \
	-Wpedantic \
	-Wextra \
	-Wall \
	-Wno-error=sequence-point \
	-Wno-error=write-strings \
	-Werror \
	-DCOMPILING_TESTS	

ifdef DEBUG
	CPPFLAGS += -DDEBUG -g
endif
help:
	@echo "test: Make & Run tests"

$(BUILD_DIR)/test: $(TEST_OBJS)
	$(CC) $(TEST_OBJS) -o $@ $(LDFLAGS)

$(BUILD_DIR)/mock: $(MOCK_OBJS)
	$(CC) $(MOCK_OBJS) -o $@ $(LDFLAGS)

$(BUILD_DIR)/example: $(EXAMPLE_OBJS)
	$(CC) $(EXAMPLE_OBJS) -o $@ $(LDFLAGS)
# c++ source
$(BUILD_DIR)/%.cpp.o: %.cpp
	$(MKDIR_P) $(dir $@)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@
	
# inosource
$(BUILD_DIR)/%.ino.o: %.ino
	$(MKDIR_P) $(dir $@)
	cp $< $@.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -I"required" -c $@.cpp -o $@
	rm $@.cpp


.PHONY: clean test benchmark example

clean:
	$(RM) -r ./build
	$(RM) *.d
	$(RM) *.o


test: $(BUILD_DIR)/test
	$(BUILD_DIR)/test -s

mock: $(BUILD_DIR)/mock
	$(BUILD_DIR)/mock
	
example: $(BUILD_DIR)/example

-include $(MOCK_DEPS) $(TEST_DEPS) 

MKDIR_P ?= mkdir -p
