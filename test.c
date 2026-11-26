#include <stdio.h>
#include <string.h>

// INTENTIONAL SECURITY VULNERABILITY:
// Hardcoded password stored in source code.
#define ADMIN_PASSWORD "Admin@12345"

int authenticate(const char *password) {
    if (strcmp(password, ADMIN_PASSWORD) == 0) {
        return 1;
    }
    return 0;
}

int main(void) {
    char enteredPassword[50];

    printf("Enter admin password: ");

    if (scanf("%49s", enteredPassword) != 1) {
        printf("Input error.\n");
        return 1;
    }

    if (authenticate(enteredPassword)) {
        printf("Access granted!\n");
    } else {
        printf("Access denied!\n");
    }

    return 0;
}
