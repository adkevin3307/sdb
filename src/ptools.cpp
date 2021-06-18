#include "ptools.h"

#include <fstream>
#include <sstream>
#include <vector>
#include <iomanip>
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

        m.permission = 0;

        if (args[1][0] == 'r') m.permission |= 0x04;
        if (args[1][0] == 'w') m.permission |= 0x02;
        if (args[1][0] == 'x') m.permission |= 0x01;

        m.node = args[4];

        m.name = basename((char*)args[5].c_str());
        loaded[m.range] = m;
    }

    file.close();

    return loaded.size();
}

ostream& operator<<(ostream& os, const map_entry_t& rhs)
{
    os << hex << setw(16) << setfill('0') << rhs.range.begin << '-';
    os << hex << setw(16) << setfill('0') << rhs.range.end << ' ';

    os << ((rhs.permission & 0x04) ? 'r' : '-');
    os << ((rhs.permission & 0x02) ? 'w' : '-');
    os << ((rhs.permission & 0x01) ? 'x' : '-');

    os << ' ';

    os << setw(9) << setfill(' ') << left << rhs.node << ' ';

    os << rhs.name;

    return os;
}
