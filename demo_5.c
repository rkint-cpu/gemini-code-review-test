#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main() {

    char name[10];

    // Vulnerability 1: Buffer Overflow
    printf("Enter your name: ");
    gets(name);

    // Vulnerability 2: Hardcoded Password
    char *password = "admin123";

    // Vulnerability 3: Unsafe String Copy
    char destination[5];
    strcpy(destination, "Hello World");

    // Vulnerability 4: Division by Zero
    int a = 10;
    int b = 0;
    int result = a / b;

    printf("Name: %s\n", name);
    printf("Password: %s\n", password);
    printf("Result: %d\n", result);

    return 0;
}
