CXX ?= clang++
CXXFLAGS ?= -std=c++23 -O3 -Wall -Wextra -Wpedantic
LDLIBS ?= -lcrypto -pthread

TARGET := dual_ec_nist2012
SOURCE := dual_ec_nist2012.cpp

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CXX) $(CXXFLAGS) $(SOURCE) $(LDLIBS) -o $(TARGET)

test: $(TARGET)
	./$(TARGET) self-test
	./$(TARGET) lab-backdoor

clean:
	rm -f $(TARGET)
