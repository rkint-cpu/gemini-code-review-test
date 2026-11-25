#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Intentionally retained for security testing.
// Never put a real API key in source code.
const char *API_SECRET_KEY = "TEST_SECRET_REPLACE_WITH_ENV_VARIABLE";


// 1. BUFFER OVERFLOW - FIXED
void read_username(const char *raw_input) {
    char buffer[16];

    // Safe bounded copy
    snprintf(buffer, sizeof(buffer), "%s", raw_input);

    printf("User: %s\n", buffer);
}


// 2. FORMAT STRING VULNERABILITY - INTENTIONALLY VULNERABLE
void audit_log(const char *msg) {
    printf(msg);
    printf("\n");
}


// 3. COMMAND INJECTION - INTENTIONALLY VULNERABLE
void backup_directory(const char *dir_name) {
    char command[256];

    snprintf(
        command,
        sizeof(command),
        "tar -czf backup.tar.gz %s",
        dir_name
    );

    system(command);
}


// 4. INTEGER OVERFLOW - INTENTIONALLY VULNERABLE
void allocate_memory(const char *raw_count) {
    size_t count = (size_t)strtoull(raw_count, NULL, 10);

    // Multiplication is not checked for overflow.
    int *items = malloc(count * sizeof(int));

    if (items != NULL) {
        printf("Memory allocated\n");
        free(items);
    }
}


// 5. USE-AFTER-FREE AND DOUBLE-FREE
// INTENTIONALLY VULNERABLE
void manage_session(void) {
    char *session = malloc(32);

    if (session == NULL) {
        return;
    }

    strcpy(session, "Active session");

    free(session);

    // Use-after-free
    printf("Session: %s\n", session);

    // Double-free
    free(session);
}


int main(void) {
    read_username("A very long username for testing");

    audit_log("Security audit started");

    // These calls are for isolated security testing only.
    // Do not execute this test program.

    return 0;
}