/* Constant format strings: none of these may be reported as format-string vulnerabilities. */
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#define LINE_FMT "%s\n"

void echo_arg(int argc, char **argv) {
    if (argc > 1) {
        printf("%s", argv[1]); /* CPP-FMT-TN-001 */
    }
}

void log_message(const char *user_msg) {
    fprintf(stderr, "%s\n", user_msg); /* CPP-FMT-TN-002 */
}

void build_label(char *buf, size_t size, const char *input) {
    snprintf(buf, size, "%s", input); /* CPP-FMT-TN-003 */
}

void build_count(char *buf, int n) {
    sprintf(buf, "%d", n); /* CPP-FMT-TN-004 */
}

void done(void) {
    printf("done\n"); /* CPP-FMT-TN-005 */
}

void newline(void) {
    fprintf(stderr, "\n"); /* CPP-FMT-TN-006 */
}

void audit(const char *msg) {
    syslog(LOG_ERR, "%s", msg); /* CPP-FMT-TN-007 */
}

void describe(char *buf, size_t size, const char *name, int id) {
    snprintf(buf, size, "user=%s id=%d", name, id); /* CPP-FMT-TN-008 */
}

void raw_line(int argc, char **argv) {
    if (argc > 1) {
        puts(argv[1]); /* CPP-FMT-TN-009 */
    }
}

void macro_format(const char *name) {
    printf(LINE_FMT, name); /* CPP-FMT-TN-010 */
}
