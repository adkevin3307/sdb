#include <iostream>
#include <map>
#include <string>
#include <sstream>
#include <vector>
#include <iomanip>
#include <fstream>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <elf.h>
#include <sys/user.h>
#include <capstone/capstone.h>

#include "types.h"
#include "ptools.h"
#include "CommandHandler.h"
#include "BreakpointHandler.h"

using namespace std;

static STATUS current_status = STATUS::NONE;
static pid_t child = -1;
static int wait_status = -1;
map<unsigned long, cs_insn> instructions;

void load_program(map<string, string>& args)
{
    if (args.find("program") == args.end()) return;

    if ((child = fork()) < 0) {
        cerr << "** [fork] error" << '\n';

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
            cerr << "** [ptrace] error, traceme" << '\n';

            exit(EXIT_FAILURE);
        }

        execvp(args["program"].c_str(), arguments.data());

        exit(EXIT_FAILURE);
    }
    else {
        waitpid(child, &wait_status, 0);
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);

        FILE* file = fopen(args["program"].c_str(), "rb");

        if (!file) {
            cerr << "** [load] error, program not found" << '\n';

            return;
        }

        int fd = fileno(file);

        Elf64_Ehdr e_header;
        fread(&e_header, 1, sizeof(e_header), file);

        vector<Elf64_Shdr> s_headers(e_header.e_shnum);
        lseek(fd, e_header.e_shoff, SEEK_SET);
        for (size_t i = 0; i < s_headers.size(); i++) {
            read(fd, &(s_headers[i]), e_header.e_shentsize);
        }

        vector<char> sh_str(s_headers[e_header.e_shstrndx].sh_size);
        lseek(fd, s_headers[e_header.e_shstrndx].sh_offset, SEEK_SET);
        read(fd, sh_str.data(), s_headers[e_header.e_shstrndx].sh_size);

        vector<char> text_buffer;
        for (auto s_header : s_headers) {
            string section_name = sh_str.data() + s_header.sh_name;

            if (section_name == ".text") {
                text_buffer.resize(s_header.sh_size);

                lseek(fd, s_header.sh_offset, SEEK_SET);
                read(fd, text_buffer.data(), s_header.sh_size);

                break;
            }
        }

        fclose(file);

        csh handle;
        cs_insn* insn;

        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
            cerr << "** [capstone] error, cs_open fail" << '\n';
        }

        size_t count = cs_disasm(handle, (unsigned char*)text_buffer.data(), text_buffer.size(), e_header.e_entry, 0, &insn);

        if (count > 0) {
            for (size_t i = 0; i < count; i++) {
                instructions[insn[i].address] = insn[i];
            }

            cs_free(insn, count);
        }
        else {
            cerr << "** [capstone] error, disassemble fail" << '\n';
        }

        current_status = STATUS::LOADED;
        cout << "** program '" << args["program"] << "' loaded. entry point 0x" << hex << e_header.e_entry << dec << '\n';
    }
}

void restore_code()
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child, 0, &regs);

    unsigned long code = ptrace(PTRACE_PEEKTEXT, child, regs.rip, 0);

    if ((code & 0xff) == 0xcc) {
        code = ((code & 0xffffffffffffff00) | BreakpointHandler::get(BreakpointHandler::find(regs.rip)).code);

        if (ptrace(PTRACE_POKETEXT, child, regs.rip, code) != 0) {
            cerr << "** [ptrace] error, restore code" << '\n';
        }
    }
}

void check_breakpoint()
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child, 0, &regs);

    unsigned long code = ptrace(PTRACE_PEEKTEXT, child, regs.rip - 1, 0);

    if ((code & 0xff) == 0xcc) {
        cout << "** breakpoint @ ";

        cs_insn instruction = instructions[regs.rip - 1];
        cout << hex << setw(12) << setfill(' ') << right << (regs.rip - 1) << ":";

        for (auto i = 0; i < 16 && i < instruction.size; i++) {
            cout << " " << hex << setw(2) << setfill('0') << (unsigned int)instruction.bytes[i];
        }

        cout << '\t' << instruction.mnemonic << '\t' << instruction.op_str << '\n';

        regs.rip -= 1;
        regs.rdx = regs.rax;

        if (ptrace(PTRACE_SETREGS, child, 0, &regs) != 0) {
            cerr << "** [ptrace] error, set regs";
        }
    }
}

int main(int argc, char* argv[])
{
    map<string, string> args = parse(argc, argv);
    load_program(args);

    fstream file;
    if (args.find("script") != args.end()) {
        file.open(args["script"]);
    }

    while (true) {
        vector<string> command;

        if (args.find("script") != args.end()) {
            command = prompt("", file);

            if (file.eof()) break;
        }
        else {
            command = prompt("> ", cin);
        }

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
                if (BreakpointHandler::size() == 0) {
                    cout << "no break point" << '\n';
                }
                else {
                    for (int i = 0; i < BreakpointHandler::size(); i++) {
                        cout << i << ": " << hex << BreakpointHandler::get(i).address << dec << '\n';
                    }
                }

                break;
            case COMMAND_TYPE::LOAD:
                if (command.size() < 2) {
                    cerr << "** [command] error, argument not enough" << '\n';

                    break;
                }

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

                restore_code();

                ptrace(PTRACE_CONT, child, 0, 0);

                if (origin_status != current_status) {
                    cout << "** pid " << child << '\n';
                }

                waitpid(child, &wait_status, 0);

                check_breakpoint();

                break;
            }
            case COMMAND_TYPE::START: {
                current_status = STATUS::RUNNING;

                cout << "** pid " << child << '\n';

                break;
            }
            case COMMAND_TYPE::BREAK: {
                if (command.size() < 2) {
                    cerr << "** [command] error, argument not enough" << '\n';

                    break;
                }

                unsigned long target = stoul(command[1], NULL, 16);
                unsigned long code = ptrace(PTRACE_PEEKTEXT, child, target, 0);

                if (BreakpointHandler::find(target) == -1) {
                    BreakpointHandler::add(target, code & 0xff);

                    if (ptrace(PTRACE_POKETEXT, child, target, (code & 0xffffffffffffff00) | 0xcc) != 0) {
                        cerr << "** [ptrace] error, set breakpoint" << '\n';
                    }
                }
                else {
                    cout << "breakpoint already exist" << '\n';
                }

                break;
            }
            case COMMAND_TYPE::CONT:
                restore_code();

                ptrace(PTRACE_CONT, child, 0, 0);
                waitpid(child, &wait_status, 0);

                check_breakpoint();

                break;
            case COMMAND_TYPE::DELETE: {
                if (command.size() < 2) {
                    cerr << "** [command] error, argument not enough" << '\n';

                    break;
                }

                int index = stoi(command[1]);

                if (index < BreakpointHandler::size()) {
                    unsigned long target = BreakpointHandler::get(index).address;
                    unsigned long code = ptrace(PTRACE_PEEKTEXT, child, target, 0);

                    code = ((code & 0xffffffffffffff00) | BreakpointHandler::get(index).code);

                    if (ptrace(PTRACE_POKETEXT, child, target, code) != 0) {
                        cerr << "** [ptrace] error, delete breakpoint" << '\n';
                    }

                    BreakpointHandler::remove(index);
                }
                else {
                    cout << "breakpoint not exist" << '\n';
                }

                break;
            }
            case COMMAND_TYPE::DISASM: {
                if (command.size() < 2) {
                    cerr << "** [command] error, argument not enough" << '\n';

                    break;
                }

                ios state(nullptr);
                state.copyfmt(cout);

                unsigned long target = stoul(command[1], NULL, 16);

                for (auto instruction : instructions) {
                    if (instruction.first >= target) {
                        cout << hex << setw(12) << setfill(' ') << right << instruction.first << ":";

                        for (auto i = 0; i < 16; i++) {
                            cout << " ";

                            if (i < instruction.second.size) {
                                cout << hex << setw(2) << setfill('0') << (unsigned int)instruction.second.bytes[i];
                            }
                            else {
                                cout << "  ";
                            }
                        }

                        cout << instruction.second.mnemonic << '\t' << instruction.second.op_str << '\n';
                    }
                }

                cout.copyfmt(state);

                break;
            }
            case COMMAND_TYPE::DUMP: {
                if (command.size() < 2) {
                    cerr << "** [command] error, argument not enough" << '\n';

                    break;
                }

                ios state(nullptr);
                state.copyfmt(cout);

                unsigned long target = stoul(command[1], NULL, 16);

                int length = 80;
                if (command.size() >= 3) {
                    length = stoi(command[2]);
                }

                for (auto i = 0; i < (int)length / 16; i++) {
                    unsigned long code[2];

                    code[0] = ptrace(PTRACE_PEEKTEXT, child, target, 0);
                    code[1] = ptrace(PTRACE_PEEKTEXT, child, target + 8, 0);

                    dump_code(target, code);
                    target += 16;
                }

                if (length % 16 != 0) {
                    unsigned long code[2];

                    code[0] = ptrace(PTRACE_PEEKTEXT, child, target, 0);
                    code[1] = ptrace(PTRACE_PEEKTEXT, child, target + 8, 0);

                    dump_code(target, code, length % 16);
                    target += (length % 16);
                }

                cout.copyfmt(state);

                break;
            }
            case COMMAND_TYPE::GET: {
                if (command.size() < 2) {
                    cerr << "** [command] error, argument not enough" << '\n';

                    break;
                }

                struct user_regs_struct regs;
                ptrace(PTRACE_GETREGS, child, 0, &regs);

                unsigned long long* target_reg = NULL;

                if (command[1] == "rax") {
                    target_reg = &(regs.rax);
                }
                else if (command[1] == "rbx") {
                    target_reg = &(regs.rbx);
                }
                else if (command[1] == "rcx") {
                    target_reg = &(regs.rcx);
                }
                else if (command[1] == "rdx") {
                    target_reg = &(regs.rdx);
                }
                else if (command[1] == "r8") {
                    target_reg = &(regs.r8);
                }
                else if (command[1] == "r9") {
                    target_reg = &(regs.r9);
                }
                else if (command[1] == "r10") {
                    target_reg = &(regs.r10);
                }
                else if (command[1] == "r11") {
                    target_reg = &(regs.r11);
                }
                else if (command[1] == "r12") {
                    target_reg = &(regs.r12);
                }
                else if (command[1] == "r13") {
                    target_reg = &(regs.r13);
                }
                else if (command[1] == "r14") {
                    target_reg = &(regs.r14);
                }
                else if (command[1] == "r15") {
                    target_reg = &(regs.r15);
                }
                else if (command[1] == "rdi") {
                    target_reg = &(regs.rdi);
                }
                else if (command[1] == "rsi") {
                    target_reg = &(regs.rsi);
                }
                else if (command[1] == "rbp") {
                    target_reg = &(regs.rbp);
                }
                else if (command[1] == "rsp") {
                    target_reg = &(regs.rsp);
                }
                else if (command[1] == "rip") {
                    target_reg = &(regs.rip);
                }
                else if (command[1] == "flags") {
                    target_reg = &(regs.eflags);
                }

                cout << command[1] << " = " << (*target_reg) << hex << " (0x" << (*target_reg) << ")" << dec << '\n';

                break;
            }
            case COMMAND_TYPE::GETREGS: {
                ios state(nullptr);
                state.copyfmt(cout);

                struct user_regs_struct regs;
                ptrace(PTRACE_GETREGS, child, 0, &regs);

                cout << hex;

                cout << "RAX " << setw(18) << left << regs.rax;
                cout << "RBX " << setw(18) << left << regs.rbx;
                cout << "RCX " << setw(18) << left << regs.rcx;
                cout << "RDX " << setw(18) << left << regs.rdx;

                cout << '\n';

                cout << "R8  " << setw(18) << left << regs.r8;
                cout << "R9  " << setw(18) << left << regs.r9;
                cout << "R10 " << setw(18) << left << regs.r10;
                cout << "R11 " << setw(18) << left << regs.r11;

                cout << '\n';

                cout << "R12 " << setw(18) << left << regs.r12;
                cout << "R13 " << setw(18) << left << regs.r13;
                cout << "R14 " << setw(18) << left << regs.r14;
                cout << "R15 " << setw(18) << left << regs.r15;

                cout << '\n';

                cout << "RDI " << setw(18) << left << regs.rdi;
                cout << "RSI " << setw(18) << left << regs.rsi;
                cout << "RBP " << setw(18) << left << regs.rbp;
                cout << "RSP " << setw(18) << left << regs.rsp;

                cout << '\n';

                cout << "RIP " << setw(18) << left << regs.rip;
                cout << "FLAGS " << setw(16) << setfill('0') << right << regs.eflags;

                cout << '\n';

                cout << dec;

                cout.copyfmt(state);

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
            case COMMAND_TYPE::SET: {
                if (command.size() < 3) {
                    cerr << "** [command] error, argument not enough" << '\n';

                    break;
                }

                struct user_regs_struct regs;
                ptrace(PTRACE_GETREGS, child, 0, &regs);

                unsigned long long* target_reg = NULL;

                if (command[1] == "rax") {
                    target_reg = &(regs.rax);
                }
                else if (command[1] == "rbx") {
                    target_reg = &(regs.rbx);
                }
                else if (command[1] == "rcx") {
                    target_reg = &(regs.rcx);
                }
                else if (command[1] == "rdx") {
                    target_reg = &(regs.rdx);
                }
                else if (command[1] == "r8") {
                    target_reg = &(regs.r8);
                }
                else if (command[1] == "r9") {
                    target_reg = &(regs.r9);
                }
                else if (command[1] == "r10") {
                    target_reg = &(regs.r10);
                }
                else if (command[1] == "r11") {
                    target_reg = &(regs.r11);
                }
                else if (command[1] == "r12") {
                    target_reg = &(regs.r12);
                }
                else if (command[1] == "r13") {
                    target_reg = &(regs.r13);
                }
                else if (command[1] == "r14") {
                    target_reg = &(regs.r14);
                }
                else if (command[1] == "r15") {
                    target_reg = &(regs.r15);
                }
                else if (command[1] == "rdi") {
                    target_reg = &(regs.rdi);
                }
                else if (command[1] == "rsi") {
                    target_reg = &(regs.rsi);
                }
                else if (command[1] == "rbp") {
                    target_reg = &(regs.rbp);
                }
                else if (command[1] == "rsp") {
                    target_reg = &(regs.rsp);
                }
                else if (command[1] == "rip") {
                    target_reg = &(regs.rip);
                }
                else if (command[1] == "flags") {
                    target_reg = &(regs.eflags);
                }

                if (command[2].substr(0, 2) == "0b") {
                    (*target_reg) = stoul(command[2], NULL, 2);
                }
                else if (command[2].substr(0, 2) == "0x") {
                    (*target_reg) = stoul(command[2], NULL, 16);
                }
                else {
                    (*target_reg) = stoul(command[2]);
                }

                if (ptrace(PTRACE_SETREGS, child, 0, &regs) != 0) {
                    cerr << "** [ptrace] error, set regs" << '\n';
                }

                break;
            }
            case COMMAND_TYPE::SI:
                restore_code();

                ptrace(PTRACE_SINGLESTEP, child, 0, 0);
                waitpid(child, &wait_status, 0);

                check_breakpoint();

                break;
            case COMMAND_TYPE::UNKNOWN:
                cerr << "** [command] error, status: ";

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

        if (WIFSTOPPED(wait_status) == 0) {
            current_status = STATUS::NONE;

            BreakpointHandler::clear();

            cout << "** child process " << child << " terminiated " << (WIFEXITED(wait_status) ? "normally" : "abnormally") << " (code " << wait_status << ")" << '\n';
        }
    }

    if (args.find("script") != args.end()) {
        file.close();
    }

    return 0;
}
