#pragma once

#include <iostream>
#include <map>
#include <string>

#include "types.h"

bool operator<(range_t r1, range_t r2);
int load_maps(pid_t pid, std::map<range_t, map_entry_t>& loaded);

std::ostream& operator<<(std::ostream& os, const map_entry_t& rhs);
