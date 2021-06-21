#pragma once

#include <vector>

struct Breakpoint {
    unsigned long address;
    unsigned long code;
};

class BreakpointHandler {
private:
    static std::vector<Breakpoint> m_breakpoints;

public:
    BreakpointHandler();
    ~BreakpointHandler();

    BreakpointHandler(BreakpointHandler const& rhs) = delete;
    BreakpointHandler(BreakpointHandler&& rhs) = delete;
    BreakpointHandler& operator=(BreakpointHandler const& rhs) = delete;
    BreakpointHandler& operator=(BreakpointHandler&& rhs) = delete;

    static void add(unsigned long address, unsigned long code);
    static void remove(int index);
    static void clear();
    static int size();
    static int find(unsigned long address);
    static Breakpoint get(int index);
};
