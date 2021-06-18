#include "CommandHandler.h"

using namespace std;

vector<CommandHandler::Command> CommandHandler::m_commands{
    Command("break", "b", (1 << STATUS::RUNNING), COMMAND_TYPE::BREAK),
    Command("cont", "c", (1 << STATUS::RUNNING), COMMAND_TYPE::CONT),
    Command("delete", "", (1 << STATUS::RUNNING), COMMAND_TYPE::DELETE),
    Command("disasm", "d", (1 << STATUS::RUNNING), COMMAND_TYPE::DISASM),
    Command("dump", "x", (1 << STATUS::RUNNING), COMMAND_TYPE::DUMP),
    Command("exit", "q", (1 << STATUS::NONE) | (1 << STATUS::LOADED) | (1 << STATUS::RUNNING), COMMAND_TYPE::EXIT),
    Command("get", "g", (1 << STATUS::RUNNING), COMMAND_TYPE::GET),
    Command("getregs", "", (1 << STATUS::RUNNING), COMMAND_TYPE::GETREGS),
    Command("help", "h", (1 << STATUS::NONE) | (1 << STATUS::LOADED) | (1 << STATUS::RUNNING), COMMAND_TYPE::HELP),
    Command("list", "l", (1 << STATUS::NONE) | (1 << STATUS::LOADED) | (1 << STATUS::RUNNING), COMMAND_TYPE::LIST),
    Command("load", "", (1 << STATUS::NONE), COMMAND_TYPE::LOAD),
    Command("run", "r", (1 << STATUS::LOADED) | (1 << STATUS::RUNNING), COMMAND_TYPE::RUN),
    Command("vmmap", "m", (1 << STATUS::RUNNING), COMMAND_TYPE::VMMAP),
    Command("set", "s", (1 << STATUS::RUNNING), COMMAND_TYPE::SET),
    Command("si", "", (1 << STATUS::RUNNING), COMMAND_TYPE::SI),
    Command("start", "", (1 << STATUS::LOADED), COMMAND_TYPE::START)
};

CommandHandler::CommandHandler()
{
}

CommandHandler::~CommandHandler()
{
}

CommandHandler::Command::Command()
{
}

CommandHandler::Command::Command(string command, string short_command, int active_status, COMMAND_TYPE command_type)
    : m_command(command), m_short_command(short_command), m_active_status(active_status), m_command_type(command_type)
{
}

CommandHandler::Command::Command(Command const& rhs)
    : CommandHandler::Command::Command(rhs.m_command, rhs.m_short_command, rhs.m_active_status, rhs.m_command_type)
{
}

CommandHandler::Command::Command(Command&& rhs)
    : CommandHandler::Command::Command(rhs.m_command, rhs.m_short_command, rhs.m_active_status, rhs.m_command_type)
{
}

CommandHandler::Command::~Command()
{
}

bool CommandHandler::Command::check(vector<string> command, STATUS status)
{
    if (this->m_command == command[0] || this->m_short_command == command[0]) {
        if (this->m_active_status & (1 << status)) {
            return true;
        }
    }

    return false;
}

COMMAND_TYPE const& CommandHandler::Command::command_type() const
{
    return this->m_command_type;
}

int CommandHandler::check(vector<string> command, STATUS status)
{
    for (size_t i = 0; i < CommandHandler::m_commands.size(); i++) {
        if (CommandHandler::m_commands[i].check(command, status)) return CommandHandler::m_commands[i].command_type();
    }

    return -1;
}
