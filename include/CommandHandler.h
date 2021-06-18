#pragma once

#include <vector>
#include <string>

#include "types.h"

class CommandHandler {
private:
    class Command {
    private:
        std::string m_command;
        std::string m_short_command;
        int m_active_status;
        COMMAND_TYPE m_command_type;

    public:
        Command();
        Command(Command const& rhs);
        Command(Command&& rhs);
        Command(std::string command, std::string short_command, int active_status, COMMAND_TYPE command_type);
        ~Command();

        Command& operator=(Command const& rhs) = delete;
        Command& operator=(Command&& rhs) = delete;

        bool check(std::vector<std::string> command, STATUS status);

        COMMAND_TYPE const& command_type() const;
    };

    static std::vector<Command> m_commands;

public:
    CommandHandler();
    ~CommandHandler();

    CommandHandler(CommandHandler const& rhs) = delete;
    CommandHandler(CommandHandler&& rhs) = delete;
    CommandHandler& operator=(CommandHandler const& rhs) = delete;
    CommandHandler& operator=(CommandHandler&& rhs) = delete;

    static COMMAND_TYPE check(std::vector<std::string> command, STATUS status);
};
