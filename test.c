#include <stdio.h>

int main(void) {
    int num1, num2;
    int sum;

    printf("Enter two integers: ");

    if (scanf("%d %d", &num1, &num2) != 2) {
        printf("Invalid input.\n");
        return 1;
    }

    sum = num1 + num2;

    printf("First number: %d\n", num1);
    printf("Second number: %d\n", num2);
    printf("Sum: %d\n", sum);

    return 0;
}
