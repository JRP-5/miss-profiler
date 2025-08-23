#include <elfutils/libdwfl.h>
#include <elfutils/libdw.h>
#include <unistd.h> 

#include "symboliser.h"

Dwfl_Callbacks s_callbacks = {
    .find_elf = dwfl_build_id_find_elf,
    .find_debuginfo = dwfl_standard_find_debuginfo,
    .section_address = dwfl_offline_section_address,
    .debuginfo_path = nullptr
};

Symboliser::Symboliser() : m_dwfl(dwfl_begin(&s_callbacks)) {
    if (!m_dwfl) {
        fprintf(stderr, "dwfl_begin failed: %s\n", dwfl_errmsg(-1));
        return;
    }

    if (dwfl_linux_proc_report(m_dwfl, getpid()) < 0) {
        fprintf(stderr, "dwfl_linux_proc_report failed: %s\n", dwfl_errmsg(-1));
    }

    if (dwfl_report_end(m_dwfl, nullptr, nullptr) != 0) {
        fprintf(stderr, "dwfl_report_end failed: %s\n", dwfl_errmsg(-1));
    }
}
Symboliser::~Symboliser() {
    if (m_dwfl) {
        dwfl_end(m_dwfl);
    }
}
namespace {

void setDsoInfo(Symbol &symbol, Dwfl_Module *mod, Dwarf_Addr ip)
{
    Dwarf_Addr moduleStart = 0;
    symbol.dso = dwfl_module_info(mod, nullptr, &moduleStart, nullptr,
                                  nullptr, nullptr, nullptr, nullptr);
    symbol.dso_offset = ip - moduleStart;
}

void setSymInfo(Symbol &symbol, Dwfl_Module *mod, Dwarf_Addr ip)
{
    GElf_Sym sym;
    auto symname = dwfl_module_addrinfo(mod, ip, &symbol.offset, &sym,
                                        nullptr, nullptr, nullptr);
    if (!symname)
        symname = "??";
    symbol.name = symname;
}

void setFileLineInfo(Symbol &symbol, Dwfl_Module *mod, Dwarf_Addr ip)
{
    Dwarf_Addr bias = 0;
    auto die = dwfl_module_addrdie(mod, ip, &bias);
    if (!die)
        return;
    auto srcloc = dwarf_getsrc_die(die, ip - bias);
    if (!srcloc)
        return;
    auto srcfile = dwarf_linesrc(srcloc, nullptr, nullptr);
    if (!srcfile)
        return;

    symbol.file = srcfile;
    dwarf_lineno(srcloc, &symbol.line);
    dwarf_linecol(srcloc, &symbol.column);
}
}
Symbol Symboliser::symbol(uint64_t ip) {
    auto *mod = dwfl_addrmodule(m_dwfl, ip);
    if (!mod) {
        // fprintf(stderr, "failed to find module for ip %zx: %s\n", ip, dwfl_errmsg(dwfl_errno()));
        return {};
    }
    Symbol symbol;
    setDsoInfo(symbol, mod, ip);
    setSymInfo(symbol, mod, ip);
    setFileLineInfo(symbol, mod, ip);
    return symbol;
}