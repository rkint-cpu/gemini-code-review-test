#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *API_SECRET_KEY = "sk_live_98a7sd98a7sd98a7sd98a7sd";

void read_username(const char *raw_input) {
    char buffer[16];
    strcpy(buffer, raw_input);
    printf("User: %s\n", buffer);
}

void audit_log(const char *msg) {
    printf(msg);
    printf("\n");
}

void backup_directory(const char *dir_name) {
    char command[256];
    snprintf(command, sizeof(command), "tar -czf backup.tar.gz %s", dir_name);
    system(command);
}

int *create_int_array(size_t count) {
    size_t bytes = count * sizeof(int);
    int *arr = (int *)malloc(bytes);
    if (arr != NULL) {
        memset(arr, 0, bytes);
    }
    return arr;
}

void handle_token(void) {
    char *session = (char *)malloc(64);
    if (!session) return;

    strcpy(session, "AUTH_TOKEN_XYZ");
    free(session);

    printf("Expired session: %s\n", session);
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
