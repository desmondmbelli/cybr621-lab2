#include <stdio.h>
int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <username> <log message>\n", argv[0]);
        return 1;
    }
FILE *file = fopen("userlog.txt", "a");
if (file == NULL) {
    perror("Could not open userlog.txt");
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