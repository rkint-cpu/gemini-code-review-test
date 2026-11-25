#include <stdio.h>
#include <string.h>

void welcome_user(char *input) {
    char username[10];

    // Intentional buffer overflow vulnerability
    strcpy(username, input);

    printf("Welcome, %s\n", username);
}

int main() {
    char name[] = "ThisIsAVeryLongUsername";

    welcome_user(name);

    return 0;
}
