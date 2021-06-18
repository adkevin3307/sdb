#include <iostream>
#include <map>
#include <string>
#include <sstream>
#include <vector>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <elf.h>

#include "types.h"
#include "ptools.h"

using namespace std;

static STATUS current_status = STATUS::NONE;
static vector<command_t> available_commands;
static pid_t child = -1;

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

void add_command(string command, string short_command, int active_status, COMMAND_TYPE command_type)
{
    command_t element;

    element.command = command;
    element.short_command = short_command;
    element.active_status = active_status;
    element.command_type = command_type;

    available_commands.push_back(element);
}

void init_command()
{
    add_command("break", "b", (1 << STATUS::RUNNING), COMMAND_TYPE::BREAK);
    add_command("cont", "c", (1 << STATUS::RUNNING), COMMAND_TYPE::CONT);
    add_command("delete", "", (1 << STATUS::RUNNING), COMMAND_TYPE::DELETE);
    add_command("disasm", "d", (1 << STATUS::RUNNING), COMMAND_TYPE::DISASM);
    add_command("dump", "x", (1 << STATUS::RUNNING), COMMAND_TYPE::DUMP);
    add_command("exit", "q", (1 << STATUS::NONE) | (1 << STATUS::LOADED) | (1 << STATUS::RUNNING), COMMAND_TYPE::EXIT);
    add_command("get", "g", (1 << STATUS::RUNNING), COMMAND_TYPE::GET);
    add_command("getregs", "", (1 << STATUS::RUNNING), COMMAND_TYPE::GETREGS);
    add_command("help", "h", (1 << STATUS::NONE) | (1 << STATUS::LOADED) | (1 << STATUS::RUNNING), COMMAND_TYPE::HELP);
    add_command("list", "l", (1 << STATUS::NONE) | (1 << STATUS::LOADED) | (1 << STATUS::RUNNING), COMMAND_TYPE::LIST);
    add_command("load", "", (1 << STATUS::NONE), COMMAND_TYPE::LOAD);
    add_command("run", "r", (1 << STATUS::LOADED) | (1 << STATUS::RUNNING), COMMAND_TYPE::RUN);
    add_command("vmmap", "m", (1 << STATUS::RUNNING), COMMAND_TYPE::VMMAP);
    add_command("set", "s", (1 << STATUS::RUNNING), COMMAND_TYPE::SET);
    add_command("si", "", (1 << STATUS::RUNNING), COMMAND_TYPE::SI);
    add_command("start", "", (1 << STATUS::LOADED), COMMAND_TYPE::START);
}

int check_command(vector<string> target_command)
{
    for (auto command : available_commands) {
        if (command.command == target_command[0] || command.short_command == target_command[0]) {
            if (command.active_status & (1 << current_status)) {
                return command.command_type;
            }
        }
    }

    return -1;
}

vector<string> shell(string prompt)
{
    string buffer;
    vector<string> command;

    cout << prompt;
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

void load_program(map<string, string>& args)
{
    if (args.find("program") == args.end()) return;

    FILE* file = fopen(args["program"].c_str(), "rb");

    if (!file) {
        cerr << "[load] error, program not found" << '\n';

        return;
    }

    Elf64_Ehdr header;
    fread(&header, 1, sizeof(header), file);

    fclose(file);

    if ((child = fork()) < 0) {
        cerr << "[fork] error" << '\n';

        exit(EXIT_FAILURE);
    }
    else if (child == 0) {
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

        exit(EXIT_SUCCESS);
    }
    else {
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACEEXEC);

        current_status = STATUS::LOADED;
        cout << "** program '" << args["program"] << "' loaded. entry point 0x" << hex << header.e_entry << '\n';

        signal(SIGCHLD, [](int signo) {
            int status;
            if (waitpid(child, &status, WNOHANG) != child) return;

            if (WIFEXITED(status)) {
                current_status = STATUS::NONE;

                int retval = WEXITSTATUS(status);
                cout << "** child process " << child << " terminiated " << (retval == 0 ? "normally" : "abnormally") << " (code " << retval << ")" << '\n';
            }
        });
    }
}

int main(int argc, char* argv[])
{
    init_command();
    map<string, string> args = parse(argc, argv);

    load_program(args);

    map<unsigned long, unsigned long> breakpoints;

    while (true) {
        vector<string> command = shell("> ");

        switch (check_command(command)) {
            case COMMAND_TYPE::EXIT:
                return 0;
            case COMMAND_TYPE::HELP:
                help_message();

                break;
            case COMMAND_TYPE::LIST:
                if (breakpoints.size() == 0) {
                    cout << "no break point" << '\n';
                }
                else {
                    int count = 0;
                    for (auto breakpoint : breakpoints) {
                        cout << (count++) << ": " << hex << breakpoint.first << '\n';
                    }
                }

                break;
            case COMMAND_TYPE::LOAD:
                args["program"] = command[1];

                args["program_arguments"] = "";
                for (size_t i = 1; i < command.size(); i++) {
                    args["program_arguments"] += command[i];

                    if (i != command.size() - 1) {
                        args["program_arguments"] += " ";
                    }
                }

                load_program(args);

                break;
            case COMMAND_TYPE::RUN:
                current_status = STATUS::RUNNING;

                ptrace(PTRACE_CONT, child, 0, 0);

                break;
            case COMMAND_TYPE::START:
                current_status = STATUS::RUNNING;

                ptrace(PTRACE_SINGLESTEP, child, 0, 0);
                cout << "** pid " << child << '\n';

                break;
            case COMMAND_TYPE::BREAK:
                break;
            case COMMAND_TYPE::CONT:
                ptrace(PTRACE_CONT, child, 0, 0);

                break;
            case COMMAND_TYPE::DELETE:
                break;
            case COMMAND_TYPE::DISASM:
                break;
            case COMMAND_TYPE::DUMP:
                break;
            case COMMAND_TYPE::GET:
                break;
            case COMMAND_TYPE::GETREGS:
                break;
            case COMMAND_TYPE::VMMAP: {
                map<range_t, map_entry_t> vmmap;

                load_maps(child, vmmap);
                for (auto element : vmmap) {
                    cout << element.second << '\n';
                }

                break;
            }
            case COMMAND_TYPE::SET:
                break;
            case COMMAND_TYPE::SI:
                break;
            case -1:
                cerr << "[command] error, status: ";

                switch (current_status) {
                    case STATUS::NONE:
                        cerr << "NONE, ";

                        break;
                    case STATUS::LOADED:
                        cerr << "LOADED, ";

                        break;
                    case STATUS::RUNNING:
                        cerr << "RUNNING, ";

                        break;
                    default:
                        break;
                }

                cerr << "'" << command[0] << "' not allow" << '\n';

                break;
            default:
                break;
        }
    }

    return 0;
}
