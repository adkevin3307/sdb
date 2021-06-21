#include "BreakpointHandler.h"

using namespace std;

vector<Breakpoint> BreakpointHandler::m_breakpoints;

BreakpointHandler::BreakpointHandler()
{
}

BreakpointHandler::~BreakpointHandler()
{
    BreakpointHandler::m_breakpoints.clear();
    BreakpointHandler::m_breakpoints.shrink_to_fit();
}

void BreakpointHandler::add(unsigned long address, unsigned long code)
{
    BreakpointHandler::m_breakpoints.push_back(
        Breakpoint {
            .address = address,
            .code = code
        }
    );
}

void BreakpointHandler::remove(int index)
{
    BreakpointHandler::m_breakpoints.erase(BreakpointHandler::m_breakpoints.begin() + index);
}

void BreakpointHandler::clear()
{
    BreakpointHandler::m_breakpoints.clear();
}

int BreakpointHandler::size()
{
    return BreakpointHandler::m_breakpoints.size();
}

int BreakpointHandler::find(unsigned long address)
{
    for (size_t i = 0; i < BreakpointHandler::m_breakpoints.size(); i++) {
        if (BreakpointHandler::m_breakpoints[i].address == address) return i;
    }

    return -1;
}

Breakpoint BreakpointHandler::get(int index)
{
    return BreakpointHandler::m_breakpoints[index];
}
