#include <stdlib.h>
#include <stdio.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define MAXBYTES 80

int main(int argc, char *argv[])
{
        fd_set readfds;
        int    num_readable;
        struct timeval tv;
        int    num_bytes;
        char   buf[MAXBYTES];
        int    fd_stdin;

        fd_stdin = fileno(stdin);

        while(1) {
                FD_ZERO(&readfds);
                FD_SET(fileno(stdin), &readfds);

                tv.tv_sec = 1;
                tv.tv_usec = 0;

                printf("Enter command: ");
                fflush(stdout);
                num_readable = select(fd_stdin + 1, &readfds, NULL, NULL, &tv);

                if (num_readable == -1) {
                        fprintf(stderr, "\nError in select : %s\n", strerror(errno));
                        exit(1);
                }
                if (num_readable == 0) {
                        printf("\nPerforming default action after 10 seconds\n");
                        break;  /* since I don't want to test forever */
                } else {
                        num_bytes = read(fd_stdin, buf, MAXBYTES);
                        if (num_bytes < 0) {
                                fprintf(stderr, "\nError on read : %s\n", strerror(errno));
                                exit(1);
                        }
                        /* process command, maybe by sscanf */
                        printf("\nRead %d  %s bytes\n", num_bytes, buf);
                        break; /* to terminate loop, since I don't process anything */
                }
        }

        return 0;
}