#include <crypt.h>
#include <ctype.h>
#include <fcntl.h>
#include <pwd.h>
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#define MAXPW 256

static int getty(char *path);
static struct passwd *getpw();

static int
getty(char *path)
{
	int fd;

	if ((fd = open(path, O_RDWR)) < 0) {
		return -1;
	}
	if ((fd = open(path, O_RDWR)) < 0) {
		return -1;
	}
	if (dup2(fd, STDOUT_FILENO) != STDOUT_FILENO) {
		return -1;
	}
	if (dup2(fd, STDIN_FILENO) != STDIN_FILENO) {
		return -1;
	}
	if (dup2(fd, STDERR_FILENO) != STDERR_FILENO) {
		return -1;
	}

	return fd;
}

static struct passwd *
getpw()
{
	struct spwd *sp;
	struct termios term;
	char user[256];
	char passwd[256];
	char *hash;
	int c, i;

	fputs("Username: ", stdout);
	i = 0;
	while((c = getchar()) != '\n' && c != EOF && i < MAXPW - 1) {
		user[i++] = c;
	}
	user[i] = '\0';
	fputs("Password: ", stdout);
	i = 0;
	tcgetattr(STDIN_FILENO, &term);
	term.c_lflag &= ~ECHO;
	tcsetattr(STDIN_FILENO, 0, &term);
	while((c = getchar()) != '\n' && c != EOF && i < MAXPW - 1) {
		passwd[i++] = c;
	}
	passwd[i] = '\0';
	if ((sp = getspnam(user)) == NULL) {
		return NULL;
	}
	term.c_lflag |= ECHO;
	tcsetattr(STDIN_FILENO, 0, &term);
	hash = crypt(passwd, sp->sp_pwdp);
	if (strcmp(hash, sp->sp_pwdp)) {
		fputs("Incorrect\n", stdout);
		return NULL;
	} else {
		fputs("Correct\n", stdout);
		return getpwnam(user);
	}
}

int
main(int argc, char *argv[])
{
	struct passwd *pw;
	char vtarg[4] = "vt";
	char WM[] = "/usr/local/bin/dwm";
	char DISPLAY[] = ":1";
	int fd, status;
	pid_t pid, shpid, Xpid, wmpid;

	if (argc < 2) {
		goto error;
	}
	if (strstr(argv[1], "/dev/tty") != argv[1] || !isdigit(argv[1][8])) {
		goto error;
	}
	vtarg[2] = argv[1][8];
	pid = fork();
	if (pid > 0) {
		exit(EXIT_SUCCESS);
	} else if (pid < 0) {
		goto error;
	}
	if (setsid() < 0) {
		goto error;
	}
	if ((fd = getty(argv[1])) < 0) {
		goto error;
	}
	while (1) {
		while(!(pw = getpw()));
		if (!pw) {
			goto error;
		}
		if ((pid = fork()) > 0) {
			wait(&status);
			continue;
		} else if (pid == 0) {
			break;
		} else {
			goto error;
		}
	}
	setuid(pw->pw_uid);
	setenv("SHELL", pw->pw_shell, 1);
	setenv("HOME", pw->pw_dir, 1);
	setenv("DISPLAY", DISPLAY, 1);
	chdir(pw->pw_dir);
	if ((shpid = fork()) == 0) {
		execl(pw->pw_shell, pw->pw_shell, "--login", (char *) NULL);
		goto error;
	} else if (pid < 0) {
		goto error;
	}
	if ((Xpid = fork()) == 0) {
		execl("/bin/Xorg", "/bin/Xorg", DISPLAY, vtarg, (char *) NULL);
		goto error;
	} else if (pid < 0) {
		goto error;
	}
	if ((wmpid = fork()) == 0) {
		execl(WM, WM, (char *) NULL);
		goto error;
	} else if (pid < 0) {
		goto error;
	}
	wait(&status);
	exit(EXIT_SUCCESS);
error:
	close(fd);
	exit(EXIT_FAILURE);
}
