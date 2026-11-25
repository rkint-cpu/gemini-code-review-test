#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main() {
    char name[10];

    // Test 1: Buffer Overflow
    printf("Enter your name: ");
    gets(name);

    // Test 2: Hardcoded Password
    char *password = "admin123";

    // Test 3: Unsafe Command Execution
    char command[100];
    strcpy(command, "echo Hello");
    system(command);

    // Test 4: Integer Division
    int a = 10;
    int b = 0;
    int result = a / b;

    printf("Name: %s\n", name);
    printf("Password: %s\n", password);
    printf("Result: %d\n", result);

    return 0;
}
