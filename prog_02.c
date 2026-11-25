#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void welcome_user(char *input) {
    char username[10];
    strcpy(username, input);
    printf("Welcome, %s\n", username);
}

void display_message(char *message) {
    printf(message);
}


void backup_file(char *filename) {
    char command[256];

    sprintf(command, "echo Backing up %s", filename);
    system(command);
}

int main() {
    char name[] = "ThisIsAVeryLongUsername";

    welcome_user(name);
    display_message("Hello from AI Security Review!");

    return 0;
}
