#include <elfutils/libdwfl.h>
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
//--> slide setDsoInfo
// 0xDEADBEEF -> libfoo @ 0xBEEF
void setDsoInfo(Symbol &symbol, Dwfl_Module *mod, Dwarf_Addr ip)
{
    Dwarf_Addr moduleStart = 0;
    symbol.dso = dwfl_module_info(mod, nullptr, &moduleStart, nullptr,
                                  nullptr, nullptr, nullptr, nullptr);
    symbol.dso_offset = ip - moduleStart;
}
//<-- slide setDsoInfo

//--> slide setSymInfo
// 0xDEADBEEF -> foobar @ 0xEF
void setSymInfo(Symbol &symbol, Dwfl_Module *mod, Dwarf_Addr ip)
{
    GElf_Sym sym;
    auto symname = dwfl_module_addrinfo(mod, ip, &symbol.offset, &sym,
                                        nullptr, nullptr, nullptr);
    if (!symname)
        symname = "??";
    symbol.name = symname;
}
//<-- slide setSymInfo

//--> slide setFileLineInfo
// 0xDEADBEEF -> foo.cpp:42
void setFileLineInfo(Symbol &symbol, Dwfl_Module *mod, Dwarf_Addr ip)
{
    Dwarf_Addr bias = 0;
    Dwarf_Addr module_base = 0;
    dwfl_module_info(mod, nullptr, &module_base, nullptr, nullptr, nullptr, nullptr, nullptr);
    fprintf(stderr, "Finding ip: 0x%lx\n", ip);
    fprintf(stderr, "Module Base: 0x%lx\n", module_base);
    auto debug_info_entry = dwfl_module_addrdie(mod, ip, &bias);
    if (!debug_info_entry){
        return;
    }
    fprintf(stderr, "Success\n");
    auto srcloc = dwarf_getsrc_die(debug_info_entry, ip - bias);
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
    if (!m_dwfl) {
        fprintf(stderr, "m_dwfl is null in symbol()!\n");
        return {};
    }
    auto *mod = dwfl_addrmodule(m_dwfl, ip);
    
    if (!mod) {
        fprintf(stderr, "failed to find module for ip %zx: %s\n",
                ip, dwfl_errmsg(dwfl_errno()));
        return {};
    }
    const char* modname = dwfl_module_info(mod, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    // fprintf(stderr, "Resolved module: %s\n", modname);
    // fprintf(stderr, "Symbolising 0x%zx\n", ip);
    Symbol symbol;
    setDsoInfo(symbol, mod, ip);
    setSymInfo(symbol, mod, ip);
    setFileLineInfo(symbol, mod, ip);

    return symbol;
}
