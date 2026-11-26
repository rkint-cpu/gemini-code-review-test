#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 1. Hardcoded credential
const char *API_KEY = "TEST_API_KEY_123456";

// 2. Buffer overflow
void get_username(void) {
    char username[16];

    printf("Enter username: ");
    gets(username);

    printf("Username: %s\n", username);
}

// 3. Format string vulnerability
void log_message(const char *message) {
    printf(message);
    printf("\n");
}

// 4. Command injection
void backup_file(const char *filename) {
    char command[256];

    sprintf(command, "echo Backing up %s", filename);

    system(command);
}

// 5. Integer overflow / unsafe allocation
void allocate_memory(unsigned int count) {
    unsigned int size = count * sizeof(int);

    int *data = malloc(size);

    if (data != NULL) {
        printf("Memory allocated\n");
        free(data);
    }
}

// 6. Use-after-free and double-free
void manage_session(void) {
    char *session = malloc(32);

    if (session == NULL) {
        return;
    }

    strcpy(session, "Active session");

    free(session);

    printf("Session: %s\n", session);

    free(session);
}

int main(void) {
    get_username();

    log_message("Application started");

    backup_file("test.txt");

    allocate_memory(100);

    manage_session();

    return 0;
}
