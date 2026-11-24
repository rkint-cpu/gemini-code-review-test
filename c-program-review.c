#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Bug 1: Hardcoded sensitive credentials
const char *ADMIN_SECRET = "SuperSecretAdminKey_2026!";

void log_event(const char *user_msg) {
    // Bug 2: Format string vulnerability (user input passed directly as format string)
    printf(user_msg);
    printf("\n");
}

int *allocate_records(unsigned int count) {
    // Bug 3: Integer overflow (count * sizeof(int) can wrap around to a small allocation)
    unsigned int total_bytes = count * sizeof(int);
    int *records = (int *)malloc(total_bytes);
    if (!records) return NULL;

    for (unsigned int i = 0; i < count; i++) {
        records[i] = i * 10;
    }
    return records;
}

void process_session(const char *token, const char *message) {
    char *session_buf = (char *)malloc(32);
    if (!session_buf) return;

    strncpy(session_buf, token, 31);
    session_buf[31] = '\0';

    if (strcmp(session_buf, ADMIN_SECRET) == 0) {
        printf("Admin access granted.\n");
    }

    free(session_buf);

    // Bug 4: Use-After-Free (reading session_buf after it has been freed)
    log_event(message);
    printf("Session token was: %s\n", session_buf);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <token> <message>\n", argv[0]);
        return 1;
    }

    int *data = allocate_records(1073741825);
    if (data) {
        free(data);
    }

    process_session(argv[1], argv[2]);
    return 0;
}
