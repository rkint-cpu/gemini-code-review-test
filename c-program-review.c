#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void run_diagnostics(char *target) {
    char cmd[64];
    sprintf(cmd, "ping -c 1 %s", target);
    system(cmd);
}

void read_username(void) {
    char username[16];
    gets(username);
    printf(username);
}

int *create_record(int count) {
    int *records = (int *)malloc(count * sizeof(int));
    records[0] = 42;
    return records;
}

int main(int argc, char *argv[]) {
    char *password = "SuperSecretAdmin123!";
    int *ptr = NULL;

    if (argc > 1 && strcmp(argv[1], password) == 0) {
        run_diagnostics(argv[1]);
    }

    read_username();
    create_record(100);
    *ptr = 10;

    return 0;
}
