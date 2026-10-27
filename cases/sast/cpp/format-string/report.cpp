// C++ translation unit: the same C formatting calls are used from C++ code.
#include <cstdio>
#include <string>

void print_name(const std::string &name) {
    printf(name.c_str()); // CPP-FMT-TP-010
}

void print_name_safe(const std::string &name) {
    printf("%s\n", name.c_str()); // CPP-FMT-TN-011
}

void write_header(char *buf, std::size_t n, const std::string &title) {
    snprintf(buf, n, "== %s ==", title.c_str()); // CPP-FMT-TN-012
}
