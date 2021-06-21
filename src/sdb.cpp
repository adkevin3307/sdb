#include <iostream>
#include <map>
#include <string>
#include <sstream>
#include <vector>
#include <iomanip>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <elf.h>
#include <sys/user.h>

#include "types.h"
#include "ptools.h"
#include "CommandHandler.h"

using namespace std;

static STATUS current_status = STATUS::NONE;
static pid_t child = -1;
static map<unsigned long, unsigned long> breakpoints;

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
        string token;
        stringstream ss;
        ss << args["program_arguments"];

        vector<char*> arguments;
        while (ss >> token) {
            arguments.push_back((char*)token.c_str());
        }
        arguments.push_back(NULL);

        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
            cerr << "[ptrace] error, traceme" << '\n';

            exit(EXIT_FAILURE);
        }

        execvp(args["program"].c_str(), arguments.data());

        exit(EXIT_SUCCESS);
    }
    else {
        int status;
        waitpid(child, &status, 0);

        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);

        current_status = STATUS::LOADED;
        cout << "** program '" << args["program"] << "' loaded. entry point 0x" << hex << header.e_entry << dec << '\n';

        signal(SIGCHLD, [](int signo) {
            int status;
            if (waitpid(child, &status, WNOHANG) != child) return;

            if (WIFEXITED(status)) {
                current_status = STATUS::NONE;

                breakpoints.clear();

                int retval = WEXITSTATUS(status);
                cout << "** child process " << child << " terminiated " << (retval == 0 ? "normally" : "abnormally") << " (code " << retval << ")" << '\n';
            }
        });
    }
}

int main(int argc, char* argv[])
{
    // TODO check argument length
    // TODO handle breakpoint, run, si, cont

    map<string, string> args = parse(argc, argv);

    load_program(args);

    unsigned long target_address = 0;

    while (true) {
        vector<string> command = prompt("> ");

        switch (CommandHandler::check(command, current_status)) {
            case COMMAND_TYPE::EXIT:
                return 0;
            case COMMAND_TYPE::HELP:
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

                break;
            case COMMAND_TYPE::LIST:
                if (breakpoints.size() == 0) {
                    cout << "no break point" << '\n';
                }
                else {
                    int count = 0;
                    for (auto breakpoint : breakpoints) {
                        cout << (count++) << ": " << hex << breakpoint.first << dec << '\n';
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
            case COMMAND_TYPE::RUN: {
                STATUS origin_status = current_status;
                current_status = STATUS::RUNNING;

                if (origin_status == current_status) {
                    cout << "** program" << args["program"] << " is already running." << '\n';
                }

                ptrace(PTRACE_CONT, child, 0, 0);

                if (origin_status != current_status) {
                    cout << "** pid " << child << '\n';
                }

                break;
            }
            case COMMAND_TYPE::START: {
                current_status = STATUS::RUNNING;

                cout << "** pid " << child << '\n';

                break;
            }
            case COMMAND_TYPE::BREAK: {
                unsigned long target = stoul(command[1], NULL, 16);
                unsigned long code = ptrace(PTRACE_PEEKTEXT, child, target, 0);

                if (breakpoints.find(target) == breakpoints.end()) {
                    breakpoints[target] = (code & 0xff);

                    if (ptrace(PTRACE_POKETEXT, child, target, (code & 0xffffffffffffff00) | 0xcc) != 0) {
                        cerr << "[ptrace] error, set breakpoint" << '\n';
                    }
                }
                else {
                    cout << "breakpoint already exist" << '\n';
                }

                break;
            }
            case COMMAND_TYPE::CONT: {
                struct user_regs_struct regs;
                ptrace(PTRACE_GETREGS, child, 0, &regs);

                cout << "now: " << hex << regs.rip - 1 << dec << '\n';
                for (auto breakpoint : breakpoints) {
                    cout << hex << breakpoint.first << ": " << breakpoint.second << dec << '\n';
                }

                unsigned long code = ptrace(PTRACE_PEEKTEXT, child, regs.rip - 1, 0);

                if ((code & 0xff) == 0xcc) {
                    code = ((code & 0xffffffffffffff00) | breakpoints[regs.rip - 1]);
                    cout << "cc: " << hex << code << dec << '\n';

                    if (ptrace(PTRACE_POKETEXT, child, regs.rip - 1, code) != 0) {
                        cerr << "[ptrace] error, restore code" << '\n';
                    }

                    regs.rip -= 1;
                    regs.rdx = regs.rax;

                    if (ptrace(PTRACE_SETREGS, child, 0, &regs) != 0) {
                        cerr << "[ptrace] error, set regs" << '\n';
                    }
                }

                ptrace(PTRACE_CONT, child, 0, 0);

                break;
            }
            case COMMAND_TYPE::DELETE: {
                unsigned long target = stoul(command[1], NULL, 16);
                unsigned long code = ptrace(PTRACE_PEEKTEXT, child, target, 0);

                if (breakpoints.find(target) == breakpoints.end()) {
                    cout << "** breakpoint not found" << '\n';
                }
                else {
                    code = ((code & 0xffffffffffffff00) | breakpoints[target]);

                    if (ptrace(PTRACE_POKETEXT, child, target, code) != 0) {
                        cerr << "[ptrace] error, delete breakpoint" << '\n';
                    }
                }

                break;
            }
            case COMMAND_TYPE::DISASM:
                break;
            case COMMAND_TYPE::DUMP:
                if (command.size() == 2) {
                    target_address = stoul(command[1], NULL, 16);
                }

                for (auto i = 0; i < 5; i++) {
                    unsigned long code[2];

                    code[0] = ptrace(PTRACE_PEEKTEXT, child, target_address, 0);
                    code[1] = ptrace(PTRACE_PEEKTEXT, child, target_address + 8, 0);

                    dump_code(target_address, code);
                    target_address += 16;
                }

                break;
            case COMMAND_TYPE::GET:
                break;
            case COMMAND_TYPE::GETREGS: {
                struct user_regs_struct regs;
                ptrace(PTRACE_GETREGS, child, 0, &regs);

                cout << hex;

                cout << "RAX " << setw(19) << left << regs.rax;
                cout << "RBX " << setw(19) << left << regs.rbx;
                cout << "RCX " << setw(19) << left << regs.rcx;
                cout << "RDX " << setw(19) << left << regs.rdx;

                cout << '\n';

                cout << "R8  " << setw(19) << left << regs.r8;
                cout << "R9  " << setw(19) << left << regs.r9;
                cout << "R10 " << setw(19) << left << regs.r10;
                cout << "R11 " << setw(19) << left << regs.r11;

                cout << '\n';

                cout << "R12 " << setw(19) << left << regs.r12;
                cout << "R13 " << setw(19) << left << regs.r13;
                cout << "R14 " << setw(19) << left << regs.r14;
                cout << "R15 " << setw(19) << left << regs.r15;

                cout << '\n';

                cout << "RDI " << setw(19) << left << regs.rdi;
                cout << "RSI " << setw(19) << left << regs.rsi;
                cout << "RBP " << setw(19) << left << regs.rbp;
                cout << "RSP " << setw(19) << left << regs.rsp;

                cout << '\n';

                cout << "RIP " << setw(19) << left << regs.rip;
                cout << "FLAGS " << setw(19) << left << regs.fs;

                cout << '\n';

                cout << dec;

                break;
            }
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
            case COMMAND_TYPE::UNKNOWN:
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
