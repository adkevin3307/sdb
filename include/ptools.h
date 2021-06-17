#pragma once

#include <iostream>
#include <map>
#include <string>
#include <sys/types.h>

typedef struct {
    unsigned long begin, end;
} range_t;

typedef struct {
    range_t range;
    int permission;
    std::string node;
    std::string name;
} map_entry_t;

bool operator<(range_t r1, range_t r2);
int load_maps(pid_t pid, std::map<range_t, map_entry_t>& loaded);

std::ostream& operator<<(std::ostream& os, const map_entry_t& rhs);
