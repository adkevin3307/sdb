#pragma once

#include <string>

enum STATUS {
    NONE,
    LOADED,
    RUNNING
};

enum COMMAND_TYPE {
    BREAK,
    CONT,
    DELETE,
    DISASM,
    DUMP,
    EXIT,
    GET,
    GETREGS,
    HELP,
    LIST,
    LOAD,
    RUN,
    VMMAP,
    SET,
    SI,
    START
};

typedef struct {
    unsigned long begin, end;
} range_t;

typedef struct {
    range_t range;
    int permission;
    std::string node;
    std::string name;
} map_entry_t;

typedef struct {
    std::string command;
    std::string short_command;
    int active_status;
    COMMAND_TYPE command_type;
} command_t;
