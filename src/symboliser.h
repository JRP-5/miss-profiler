#include <string>

struct Dwfl;

struct Symbol
{
    std::string name;
    uint64_t offset = 0;
    std::string dso;
    uint64_t dso_offset = 0;
    std::string file;
    int line = 0;
    int column = 0;
};
class Symboliser {
public:
    Symboliser(pid_t child_pid);
    ~Symboliser();
    Symbol symbol(uint64_t ip);
    std::string demangle(const std::string &symbol) const; 
// private:
    Dwfl *m_dwfl;
};