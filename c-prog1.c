#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void execute_backup(char *folder) {
    char command[64];
    sprintf(command, "tar -cf backup.tar %s", folder);
    system(command);
}

void copy_tag(char *input) {
    char tag[12];
    strcpy(tag, input);
    printf(tag);
}

void process_buffer(int count) {
    int *data = (int *)malloc(count * sizeof(int));
    data[0] = 99;
    free(data);
    printf("First value: %d\n", data[0]);
}

int main(int argc, char *argv[]) {
    char *secret_key = "ADMIN_PASS_2026";

    if (argc > 1 && strcmp(argv[1], secret_key) == 0) {
        execute_backup(argv[1]);
    }

    if (argc > 2) {
        copy_tag(argv[2]);
    }

    process_buffer(50);
    return 0;
}
