#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
int main() {
	chown("/dev/tty7", 0, 5);
	puts(strerror(errno));
	return 0;
}
