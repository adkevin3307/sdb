EXE = sdb
OBJ_DIR = obj
TRASH = .cache

SOURCES = $(wildcard src/*.cpp)
OBJS = $(addprefix $(OBJ_DIR)/, $(patsubst %.cpp, %.o, $(notdir $(SOURCES))))

CXXFLAGS = -std=c++17 -Iinclude -O3 -Wall

LIBS = -lcapstone

all: create_object_directory $(EXE)
	@echo Compile Success

create_object_directory:
	mkdir -p $(OBJ_DIR)

$(OBJ_DIR)/%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(EXE): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -rf $(EXE) $(OBJ_DIR) $(TRASH)
