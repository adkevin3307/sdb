#pragma once

#include <iostream>
#include <map>
#include <string>
#include <vector>

#include "types.h"

std::map<std::string, std::string> parse(int argc, char* argv[]);
std::vector<std::string> prompt(std::string message);
void dump_code(unsigned long addr, unsigned long code[]);
int load_maps(pid_t pid, std::map<range_t, map_entry_t>& loaded);

bool operator<(range_t r1, range_t r2);
std::ostream& operator<<(std::ostream& os, const map_entry_t& rhs);
