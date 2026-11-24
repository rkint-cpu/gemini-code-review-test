#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 1. Hardcoded Credentials (CWE-798)
const char *ADMIN_PASSWORD = "SuperSecretAdminPassword123!";

// 2. Stack Buffer Overflow (CWE-120) & Unsafe gets() (CWE-242)
void greet_user(void) {
    char username[16];
    printf("Enter username: ");
    gets(username); // Unbounded write into 16-byte buffer
    printf("Welcome, %s!\n", username);
}

// 3. Format String Vulnerability (CWE-134)
void log_message(const char *user_input) {
    printf(user_input); // User-controlled format string
    printf("\n");
}

// 4. OS Command Injection (CWE-78)
void check_host(const char *hostname) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ping -c 1 %s", hostname);
    system(cmd); // Unsanitized shell command execution
}

// 5. Integer Overflow Leading to Heap Buffer Overflow (CWE-190 / CWE-122)
char *allocate_records(size_t count, size_t record_size) {
    size_t total_bytes = count * record_size; // Can wrap around on 32/64-bit multiplication
    char *buffer = (char *)malloc(total_bytes);
    if (buffer != NULL) {
        memset(buffer, 0, total_bytes);
    }
    return buffer;
}

// 6. Use-After-Free & Double Free (CWE-416 / CWE-415)
void process_session(void) {
    char *token = (char *)malloc(32);
    if (!token) return;

    strcpy(token, "SESSION_ACTIVE_9981");
    free(token);

    // Use-after-free read
    printf("Session token: %s\n", token);

    // Double free
    free(token);
}

int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], ADMIN_PASSWORD) == 0) {
        greet_user();
        log_message(argv[1]);
        check_host("127.0.0.1");
    }

    char *records = allocate_records(10, 64);
    free(records);

    process_session();
    return 0;
}
