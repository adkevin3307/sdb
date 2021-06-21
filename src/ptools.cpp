#include "ptools.h"

#include <fstream>
#include <sstream>
#include <vector>
#include <iomanip>
#include <libgen.h>
#include <unistd.h>

using namespace std;

map<string, string> parse(int argc, char* argv[])
{
    int opt = 0;
    map<string, string> args;

    while ((opt = getopt(argc, argv, "s:")) != -1) {
        switch (opt) {
            case 's':
                args["script"] = optarg;

                break;
            default:
                break;
        }
    }

    if (optind < argc) {
        args["program"] = argv[optind];
        args["program_arguments"] = "";

        for (auto i = optind; i < argc; i++) {
            args["program_arguments"] += argv[i];

            if (i != argc - 1) {
                args["program_arguments"] += " ";
            }
        }
    }

    return args;
}

vector<string> prompt(string message)
{
    usleep(3000);

    string buffer;
    vector<string> command;

    cout << message;
    getline(cin, buffer);

    stringstream ss;
    ss << buffer;

    string token;
    while (ss >> token) {
        command.push_back(token);
    }

    return command;
}

void dump_code(unsigned long addr, unsigned long code[])
{
    printf("\t%lx:", addr);

    for (auto i = 0; i < 16; i++) {
        printf(" %02x", ((unsigned char*)code)[i]);
    }

    printf("  ");

    printf("|");
    for (auto i = 0; i < 16; i++) {
        char c = ((char*)code)[i];

        printf("%c", isprint(c) ? c : '.');
    }
    printf("|");

    printf("\n");
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
        if (args[1][1] == 'w') m.permission |= 0x02;
        if (args[1][2] == 'x') m.permission |= 0x01;

		m.offset = stol(args[2], NULL, 16);

        m.node = args[4];
        m.name = args[5];

        loaded[m.range] = m;
    }

    file.close();

    return loaded.size();
}

bool operator<(range_t r1, range_t r2)
{
    return (r1.begin < r2.begin && r1.end < r2.end);
}

ostream& operator<<(ostream& os, const map_entry_t& rhs)
{
    os << hex << setw(16) << setfill('0') << right << rhs.range.begin << dec << '-';
    os << hex << setw(16) << setfill('0') << right << rhs.range.end << dec << ' ';

    os << ((rhs.permission & 0x04) ? 'r' : '-');
    os << ((rhs.permission & 0x02) ? 'w' : '-');
    os << ((rhs.permission & 0x01) ? 'x' : '-');

    os << ' ';

    os << setw(9) << setfill(' ') << left << rhs.node << ' ';

    os << rhs.name;

    return os;
}
