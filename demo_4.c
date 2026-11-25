#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(void) {

    char name[10];

    // Fix 1: Safe input using fgets()
    printf("Enter your name: ");

    if (fgets(name, sizeof(name), stdin) == NULL) {
        printf("Input error.\n");
        return 1;
    }

    name[strcspn(name, "\n")] = '\0';

    // Fix 2: Read password from environment variable
    const char *password = getenv("APP_PASSWORD");

    if (password == NULL) {
        printf("Password is not configured.\n");
    }

    // Fix 3: Safe bounded string copy
    char destination[5];

    snprintf(destination, sizeof(destination), "%s", "Hello");

    // Fix 4: Check divisor before division
    int a = 10;
    int b = 2;

    if (b != 0) {
        int result = a / b;
        printf("Result: %d\n", result);
    } else {
        printf("Division by zero is not allowed.\n");
    }

    printf("Name: %s\n", name);
    printf("Copied string: %s\n", destination);

    return 0;
}
