#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <username> <log message>\n", argv[0]);
        return 1;
    }

    /* REMEDIATION 2: reject CR/LF in either field to block log injection */
    if (strpbrk(argv[1], "\r\n") != NULL || strpbrk(argv[2], "\r\n") != NULL) {
        fprintf(stderr, "Error: newline characters are not allowed\n");
        return 1;
    }

    /* REMEDIATION 1: create the log with explicit owner-only mode (0600)
       instead of fopen()'s default 0666, so umask/ACLs cannot widen it */
    int fd = open("userlog.txt", O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        perror("Could not open userlog.txt");
        return 1;
    }
    FILE *file = fdopen(fd, "a");
    if (file == NULL) {
        perror("Could not open userlog.txt stream");
        close(fd);
        return 1;
    }

    if (fprintf(file, "%s: %s\n", argv[1], argv[2]) < 0) {
        perror("Could not write to userlog.txt");
        fclose(file);
        return 1;
    }

    if (fclose(file) == EOF) {
        perror("Could not close userlog.txt");
        return 1;
    }

    return 0;
}
