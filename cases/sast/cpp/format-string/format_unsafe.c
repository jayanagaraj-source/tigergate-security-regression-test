/* CPP-002 / CPP-027 positives: a non-literal value used as the format string. */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

void echo_arg(int argc, char **argv) {
    if (argc > 1) {
        printf(argv[1]); /* CPP-FMT-TP-001 */
    }
}

void log_message(const char *user_msg) {
    fprintf(stderr, user_msg); /* CPP-FMT-TP-002 */
}

void build_label(char *buf, size_t size, const char *input) {
    snprintf(buf, size, input); /* CPP-FMT-TP-003 */
}

void build_legacy(char *buf, const char *input) {
    sprintf(buf, input); /* CPP-FMT-TP-004 */
}

void audit(const char *msg) {
    syslog(LOG_ERR, msg); /* CPP-FMT-TP-005 */
}

void audit_v(const char *fmt, va_list ap) {
    vsyslog(LOG_INFO, fmt, ap); /* CPP-FMT-TP-006 */
}

void greeting(void) {
    printf(getenv("GREETING")); /* CPP-FMT-TP-007 */
}

void replay(FILE *in, FILE *logf) {
    char line[256];
    while (fgets(line, sizeof line, in) != NULL) {
        fprintf(logf, line); /* CPP-FMT-TP-008 */
    }
}

void field_label(char *out, size_t n, char **fields, int i) {
    snprintf(out, n, fields[i]); /* CPP-FMT-TP-009 */
}

void counted(int argc, char **argv) {
    if (argc > 1) {
        printf(argv[1], argc); /* CPP-FMT-GAP-001 */
    }
}
