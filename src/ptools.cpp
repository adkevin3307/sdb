#include "ptools.h"

#include <map>
#include <string>
#include <fstream>
#include <sstream>
#include <vector>

#include <stdio.h>
#include <libgen.h>

using namespace std;

bool operator<(range_t r1, range_t r2)
{
    return (r1.begin < r2.begin && r1.end < r2.end);
}

int load_maps(pid_t pid, map<range_t, map_entry_t>& loaded)
{
    string filename = "/proc/" + to_string(pid) + "/maps";

    fstream file;
    file.open(filename, ios::in);

    if (!file.is_open()) return -1;

    string buffer;

    while (getline(file, buffer)) {
        string token;
        stringstream ss;
        vector<string> args;
        map_entry_t m;

        ss << buffer;

        while (ss >> token) {
            args.push_back(token);
        }

        if (args.size() < 6) continue;

        auto it = args[0].find('-');
        if (it != string::npos) {
            m.range.begin = strtol(args[0].substr(0, it).c_str(), NULL, 16);
            m.range.end = strtol(args[0].substr(it + 1).c_str(), NULL, 16);
        }

        m.name = basename((char*)args[5].c_str());
        m.perm = 0;

        if (args[1][0] == 'r') m.perm |= 0x04;
        if (args[1][0] == 'w') m.perm |= 0x02;
        if (args[1][0] == 'x') m.perm |= 0x01;

        m.offset = strtol(args[2].c_str(), NULL, 16);

        loaded[m.range] = m;

        printf("XXX: %lx-%lx %04o %s\n", m.range.begin, m.range.end, m.perm, m.name.c_str());
    }

    file.close();

    return loaded.size();
}
