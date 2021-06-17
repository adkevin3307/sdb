#include <iostream>
#include <map>
#include <string>
#include <sstream>
#include <vector>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

// #include <assert.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <sys/types.h>
// #include <sys/user.h>

#include "ptools.h"

using namespace std;

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

    if (optind >= argc) {
        cerr << "[arg] error, no program given" << '\n';

        exit(EXIT_FAILURE);
    }

    args["program"] = argv[optind];
    args["program_arguments"] = "";

    for (auto i = optind; i < argc; i++) {
        args["program_arguments"] += argv[i];

        if (i != argc - 1) {
            args["program_arguments"] += " ";
        }
    }

    return args;
}

int main(int argc, char* argv[])
{
    map<string, string> args = parse(argc, argv);

    pid_t child;

    if ((child = fork()) < 0) {
        cerr << "[fork] error" << '\n';

        exit(EXIT_FAILURE);
    }

    if (child == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
            cerr << "[ptrace] error, traceme" << '\n';

            exit(EXIT_FAILURE);
        }

        string token;
        stringstream ss;
        ss << args["program_arguments"];

        vector<char*> arguments;
        while (ss >> token) {
            arguments.push_back((char*)token.c_str());
        }
        arguments.push_back(NULL);

        execvp(args["program"].c_str(), arguments.data());
    }
    else {
        map<range_t, map_entry_t> vmmap;

        load_maps(child, vmmap);
        for (auto element : vmmap) {
            cout << element.second << '\n';
        }

        while (true) {
            int status;

            pid_t wpid = waitpid(child, &status, WNOHANG);
            if (wpid == child) break;
        }
    }

    // unsigned long baseaddr, target, code;
    // map<range_t, map_entry_t> vmmap;
    // map<range_t, map_entry_t>::iterator vi;

    // if (waitpid(child, &status, 0) < 0) errquit("waitpid");
    // assert(WIFSTOPPED(status));
    // ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);

    // if (load_maps(child, vmmap) <= 0) {
    // fprintf(stderr, "## cannot load memory mappings.\n");
    // return -1;
    // }
    // fprintf(stderr, "## %zu map entries loaded.\n", vmmap.size());

    // for (vi = vmmap.begin(); vi != vmmap.end(); vi++) {
    // if (vi->second.name == "guess" && vi->second.offset == 0 && (vi->second.perm & 0x01) == 0x01) {
    // baseaddr = vi->second.range.begin;
    // break;
    // }
    // }
    // target = baseaddr + offset;
    // fprintf(stderr, "## baseaddr = 0x%zx, target = 0x%zx.\n", baseaddr, target);

    // [> get original text: 48 39 d0 <]
    // code = ptrace(PTRACE_PEEKTEXT, child, target, 0);
    // dump_code(target, code);
    // [> set break point <]
    // if (ptrace(PTRACE_POKETEXT, child, target, (code & 0xffffffffffffff00) | 0xcc) != 0)
    // errquit("ptrace(POKETEXT)");

    // [> continue the execution <]
    // ptrace(PTRACE_CONT, child, 0, 0);

    // while (waitpid(child, &status, 0) > 0) {
    // struct user_regs_struct regs;
    // if (!WIFSTOPPED(status)) continue;
    // if (ptrace(PTRACE_GETREGS, child, 0, &regs) != 0)
    // errquit("ptrace(GETREGS)");
    // if (regs.rip - 1 == target) {
    // [> restore break point <]
    // if (ptrace(PTRACE_POKETEXT, child, target, code) != 0)
    // errquit("ptrace(POKETEXT)");
    // [> set registers <]
    // regs.rip = regs.rip - 1;
    // regs.rdx = regs.rax;
    // if (ptrace(PTRACE_SETREGS, child, 0, &regs) != 0) errquit("ptrace(SETREGS)");
    // }
    // ptrace(PTRACE_CONT, child, 0, 0);
    // }

    return 0;
}
