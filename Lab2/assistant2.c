#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE /* for flock() */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>


#define LOG_FILENAME     "userlog.txt"
#define MAX_USERNAME_LEN 32U    /* maximum characters in a username        */
#define MAX_MESSAGE_LEN  1024U  /* maximum characters in a log message     */
#define TIMESTAMP_LEN    32U    /* buffer size for an ISO-8601 timestamp   */

/* Full line: timestamp + separators + username + message + newline + NUL. */
#define MAX_LINE_LEN (TIMESTAMP_LEN + MAX_USERNAME_LEN + MAX_MESSAGE_LEN + 32U)

/* ---- Input validation --------------------------------------------------- */

/*
 * Return 1 if the character is allowed in a username, 0 otherwise.
 * Explicit ASCII ranges are used instead of isalnum() so the result does not
 * depend on the current locale.
 */
static int is_valid_username_char(char c)
{
    return (c >= 'a' && c <= 'z') ||
           (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') ||
           c == '_' || c == '-' || c == '.';
}

/*
 * Validate the username:
 *   - not NULL, not empty
 *   - no longer than MAX_USERNAME_LEN
 *   - only [A-Za-z0-9_.-]
 *   - does not start with '-' or '.' (avoids option-like or hidden names)
 * Return 0 on success, -1 on failure (with an error message on stderr).
 */
static int validate_username(const char *username)
{
    size_t len;
    size_t i;

    if (username == NULL) {
        fprintf(stderr, "Error: username is missing.\n");
        return -1;
    }

    /* strnlen() never reads past MAX_USERNAME_LEN + 1 bytes. */
    len = strnlen(username, MAX_USERNAME_LEN + 1U);

    if (len == 0U) {
        fprintf(stderr, "Error: username must not be empty.\n");
        return -1;
    }
    if (len > MAX_USERNAME_LEN) {
        fprintf(stderr, "Error: username exceeds %u characters.\n",
                MAX_USERNAME_LEN);
        return -1;
    }
    if (username[0] == '-' || username[0] == '.') {
        fprintf(stderr, "Error: username must not start with '-' or '.'.\n");
        return -1;
    }

    for (i = 0; i < len; i++) {
        if (!is_valid_username_char(username[i])) {
            fprintf(stderr,
                    "Error: username may only contain letters, digits, "
                    "'_', '-' and '.'.\n");
            return -1;
        }
    }

    return 0;
}

/*
 * Validate the log message:
 *   - not NULL, not empty
 *   - no longer than MAX_MESSAGE_LEN
 *   - only printable ASCII (0x20..0x7E); this rejects newlines, carriage
 *     returns, tabs, escape sequences and other control characters that
 *     could be used for log injection or terminal manipulation.
 * Return 0 on success, -1 on failure (with an error message on stderr).
 */
static int validate_message(const char *message)
{
    size_t len;
    size_t i;

    if (message == NULL) {
        fprintf(stderr, "Error: message is missing.\n");
        return -1;
    }

    len = strnlen(message, MAX_MESSAGE_LEN + 1U);

    if (len == 0U) {
        fprintf(stderr, "Error: message must not be empty.\n");
        return -1;
    }
    if (len > MAX_MESSAGE_LEN) {
        fprintf(stderr, "Error: message exceeds %u characters.\n",
                MAX_MESSAGE_LEN);
        return -1;
    }

    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)message[i];
        if (c < 0x20U || c > 0x7EU) {
            fprintf(stderr,
                    "Error: message contains non-printable or control "
                    "characters (position %zu).\n", i);
            return -1;
        }
    }

    return 0;
}

/* ---- Helpers ------------------------------------------------------------ */

/*
 * Write a UTC ISO-8601 timestamp (e.g. 2026-10-04T12:34:56Z) into buf.
 * Return 0 on success, -1 on failure.
 */
static int make_timestamp(char *buf, size_t bufsize)
{
    time_t now;
    struct tm tm_utc;

    if (buf == NULL || bufsize == 0U) {
        return -1;
    }

    now = time(NULL);
    if (now == (time_t)-1) {
        perror("Error: time");
        return -1;
    }

    /* gmtime_r() is the thread-safe, reentrant variant of gmtime(). */
    if (gmtime_r(&now, &tm_utc) == NULL) {
        fprintf(stderr, "Error: could not convert time.\n");
        return -1;
    }

    /* strftime() returns 0 if the result did not fit. */
    if (strftime(buf, bufsize, "%Y-%m-%dT%H:%M:%SZ", &tm_utc) == 0U) {
        fprintf(stderr, "Error: timestamp buffer too small.\n");
        return -1;
    }

    return 0;
}

/*
 * Write exactly len bytes from buf to fd, retrying on partial writes and
 * on interruption by signals (EINTR).
 * Return 0 on success, -1 on failure.
 */
static int write_all(int fd, const char *buf, size_t len)
{
    size_t total = 0U;

    while (total < len) {
        ssize_t n = write(fd, buf + total, len - total);

        if (n < 0) {
            if (errno == EINTR) {
                continue;           /* interrupted: retry the write */
            }
            perror("Error: write");
            return -1;
        }
        if (n == 0) {
            fprintf(stderr, "Error: write made no progress.\n");
            return -1;
        }
        total += (size_t)n;
    }

    return 0;
}

/*
 * Close fd, reporting errors. Return 0 on success, -1 on failure.
 * close() is not retried on EINTR because on Linux the descriptor is
 * released regardless, and retrying could close an unrelated descriptor.
 */
static int safe_close(int fd)
{
    if (close(fd) != 0) {
        perror("Error: close");
        return -1;
    }
    return 0;
}

/* ---- Core logic --------------------------------------------------------- */

/*
 * Append one formatted entry to LOG_FILENAME.
 * Format: <timestamp> user=<username> msg=<message>\n
 * Return 0 on success, -1 on failure.
 */
static int append_log_entry(const char *username, const char *message)
{
    char timestamp[TIMESTAMP_LEN];
    char line[MAX_LINE_LEN];
    int  line_len;
    int  fd;
    int  status = -1;
    struct stat st;

    /* Build the complete line first so it is written with one append. */
    if (make_timestamp(timestamp, sizeof(timestamp)) != 0) {
        return -1;
    }

    line_len = snprintf(line, sizeof(line), "%s user=%s msg=%s\n",
                        timestamp, username, message);

    /* snprintf() returns a negative value on error, or the length it would
     * have written; a value >= buffer size means the output was truncated. */
    if (line_len < 0) {
        fprintf(stderr, "Error: failed to format log entry.\n");
        return -1;
    }
    if ((size_t)line_len >= sizeof(line)) {
        fprintf(stderr, "Error: log entry too long.\n");
        return -1;
    }

    /*
     * Open flags:
     *   O_WRONLY   - write only, never read
     *   O_APPEND   - every write goes atomically to the end of the file
     *   O_CREAT    - create the file if it does not exist
     *   O_NOFOLLOW - fail if the final path component is a symlink
     *   O_NOCTTY   - never become the controlling terminal
     *   O_CLOEXEC  - do not leak the descriptor into child processes
     * Mode 0600   - new file readable/writable by the owner only
     */
    do {
        fd = open(LOG_FILENAME,
                  O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW |
                  O_NOCTTY | O_CLOEXEC,
                  S_IRUSR | S_IWUSR);
    } while (fd < 0 && errno == EINTR);

    if (fd < 0) {
        if (errno == ELOOP) {
            fprintf(stderr, "Error: %s is a symbolic link; refusing to "
                            "write.\n", LOG_FILENAME);
        } else {
            perror("Error: open " LOG_FILENAME);
        }
        return -1;
    }

    /* Check the object we actually opened (no race with a path check). */
    if (fstat(fd, &st) != 0) {
        perror("Error: fstat");
        goto cleanup;
    }
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "Error: %s is not a regular file.\n", LOG_FILENAME);
        goto cleanup;
    }
    if (st.st_nlink != 1) {
        fprintf(stderr, "Error: %s has multiple hard links; refusing to "
                        "write.\n", LOG_FILENAME);
        goto cleanup;
    }

    /* Take an exclusive lock so concurrent instances do not interleave. */
    while (flock(fd, LOCK_EX) != 0) {
        if (errno != EINTR) {
            perror("Error: flock");
            goto cleanup;
        }
    }

    if (write_all(fd, line, (size_t)line_len) != 0) {
        goto unlock;
    }

    /* Flush the data to stable storage before reporting success. */
    if (fsync(fd) != 0) {
        perror("Error: fsync");
        goto unlock;
    }

    status = 0;

unlock:
    if (flock(fd, LOCK_UN) != 0) {
        perror("Error: flock unlock");
        status = -1;
    }

cleanup:
    if (safe_close(fd) != 0) {
        status = -1;
    }
    return status;
}

/* ---- Entry point -------------------------------------------------------- */

int main(int argc, char *argv[])
{
    const char *prog = (argc > 0 && argv[0] != NULL) ? argv[0] : "userlog";

    /* Exactly two arguments are required: username and message. */
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <username> <message>\n", prog);
        fprintf(stderr, "  username: 1-%u chars of [A-Za-z0-9_.-]\n",
                MAX_USERNAME_LEN);
        fprintf(stderr, "  message : 1-%u printable ASCII characters\n",
                MAX_MESSAGE_LEN);
        return EXIT_FAILURE;
    }

    if (validate_username(argv[1]) != 0) {
        return EXIT_FAILURE;
    }
    if (validate_message(argv[2]) != 0) {
        return EXIT_FAILURE;
    }

    if (append_log_entry(argv[1], argv[2]) != 0) {
        fprintf(stderr, "Error: failed to write log entry.\n");
        return EXIT_FAILURE;
    }

    /* Report success, and make sure stdout was flushed correctly. */
    if (printf("Log entry written to %s\n", LOG_FILENAME) < 0 ||
        fflush(stdout) != 0) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}