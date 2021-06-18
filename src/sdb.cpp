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
#include "CommandHandler.h"

using namespace std;

static STATUS current_status = STATUS::NONE;
static pid_t child = -1;

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
    map<string, string> args = parse(argc, argv);

    load_program(args);

    map<unsigned long, unsigned long> breakpoints;

    while (true) {
        vector<string> command = prompt("> ");

        switch (CommandHandler::check(command, current_status)) {
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
