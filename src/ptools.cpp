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

void help_message()
{
    cout << "- break {instruction-address}: add a break point" << '\n';
    cout << "- cont: continue execution" << '\n';
    cout << "- delete {break-point-id}: remove a break point" << '\n';
    cout << "- disasm addr: disassemble instructions in a file or a memory region" << '\n';
    cout << "- dump addr [length]: dump memory content" << '\n';
    cout << "- exit: terminate the debugger" << '\n';
    cout << "- get reg: get a single value from a register" << '\n';
    cout << "- getregs: show registers" << '\n';
    cout << "- help: show this message" << '\n';
    cout << "- list: list break points" << '\n';
    cout << "- load {path/to/a/program}: load a program" << '\n';
    cout << "- run: run the program" << '\n';
    cout << "- vmmap: show memory layout" << '\n';
    cout << "- set reg val: get a single value to a register" << '\n';
    cout << "- si: step into instruction" << '\n';
    cout << "- start: start the program and stop at the first instruction" << '\n';
}

void dump_code(long addr, long code)
{
    fprintf(stderr, "## %lx: code = %02x %02x %02x %02x %02x %02x %02x %02x\n",
            addr,
            ((unsigned char*)(&code))[0],
            ((unsigned char*)(&code))[1],
            ((unsigned char*)(&code))[2],
            ((unsigned char*)(&code))[3],
            ((unsigned char*)(&code))[4],
            ((unsigned char*)(&code))[5],
            ((unsigned char*)(&code))[6],
            ((unsigned char*)(&code))[7]);
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

bool operator<(range_t r1, range_t r2)
{
    return (r1.begin < r2.begin && r1.end < r2.end);
}

ostream& operator<<(ostream& os, const map_entry_t& rhs)
{
    os << hex << setw(16) << setfill('0') << rhs.range.begin << dec << '-';
    os << hex << setw(16) << setfill('0') << rhs.range.end << dec << ' ';

    os << ((rhs.permission & 0x04) ? 'r' : '-');
    os << ((rhs.permission & 0x02) ? 'w' : '-');
    os << ((rhs.permission & 0x01) ? 'x' : '-');

    os << ' ';

    os << setw(9) << setfill(' ') << left << rhs.node << ' ';

    os << rhs.name;

    return os;
}
