#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 1. Hardcoded API Secret (CWE-798)
const char *API_SECRET_KEY = "sk_live_98a7sd98a7sd98a7sd98a7sd";

// 2. Stack Buffer Overflow via gets() and strcpy() (CWE-120 / CWE-242)
void read_username(const char *raw_input) {
    char buffer[16];
    strcpy(buffer, raw_input); // No bounds check
    printf("User: %s\n", buffer);
}

// 3. Format String Vulnerability (CWE-134)
void audit_log(const char *msg) {
    printf(msg); // User-controlled format string
    printf("\n");
}

// 4. OS Command Injection (CWE-78)
void backup_directory(const char *dir_name) {
    char command[256];
    snprintf(command, sizeof(command), "tar -czf backup.tar.gz %s", dir_name);
    system(command); // Unsanitized input passed to shell
}

// 5. Integer Overflow Leading to Heap Buffer Overflow (CWE-190 / CWE-122)
int *create_int_array(size_t count) {
    size_t bytes = count * sizeof(int); // Can wrap around on multiplication
    int *arr = (int *)malloc(bytes);
    if (arr != NULL) {
        memset(arr, 0, bytes);
    }
    return arr;
}

// 6. Use-After-Free & Double Free (CWE-416 / CWE-415)
void handle_token(void) {
    char *session = (char *)malloc(64);
    if (!session) return;

    strcpy(session, "AUTH_TOKEN_XYZ");
    free(session);

    // Use-after-free read
    printf("Expired session: %s\n", session);

    // Double free
    free(session);
}

int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], API_SECRET_KEY) == 0) {
        read_username(argv[1]);
        audit_log(argv[1]);
        backup_directory("/tmp/data");
    }

    int *nums = create_int_array(10);
    free(nums);

    handle_token();
    return 0;
}
