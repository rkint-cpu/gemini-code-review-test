#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void greet_user(const char *input) {
    char username[16];
    // Bug 1: Buffer overflow (unchecked strcpy into fixed 16-byte buffer)
    strcpy(username, input);
    printf("Welcome, %s!\n", username);
}

void run_diagnostics(const char *host) {
    char cmd[120];
    // Bug 2: Command injection via unsanitized input passed to system()
    snprintf(cmd, sizeof(cmd), "ping -c 1 %s", host);
    system(cmd);
}

void process_scores(int count) {
    int *scores = (int *)malloc(count * sizeof(int));
    // Bug 3: Potential NULL pointer dereference (no check if malloc failed)
    scores[0] = 100;
    printf("Top score: %d\n", scores[0]);
    // Bug 4: Memory leak (allocated heap memory is never freed)
}

int main(int argc, char *argv[]) {
    if (argc > 2) {
        greet_user(argv[1]);
        run_diagnostics(argv[2]);
    }
    process_scores(5);
    return 0;
}
