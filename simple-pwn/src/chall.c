#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win(void) {
    FILE *flag = fopen("/flag", "r");
    int ch;

    if (flag == NULL) {
        puts("flag file missing");
        exit(1);
    }

    while ((ch = fgetc(flag)) != EOF) {
        putchar(ch);
    }
    fclose(flag);
}

void vuln(void) {
    char name[64];

    puts("Simple Pwn");
    printf("gift: %p\n", (void *)win);
    puts("name:");
    fflush(stdout);

    read(STDIN_FILENO, name, 256);
    puts("bye");
}

int main(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    vuln();
    return 0;
}
