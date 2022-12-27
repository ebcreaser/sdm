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

#define SDM_MAXPW 256
#define SDM_DISPLAY ":1"
#define SDM_WM "/usr/local/bin/dwm"

static int getty(char *path);
static struct passwd *getpw();
static int runsession(struct passwd *pw, char vtn);

/* open tty device at path and set stdin, stdout, and stderr
 */
static int
getty(char *path)
{
	int fd;

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

/* prompt user for username and password, and authenticate against shadow file
 */
static struct passwd *
getpw()
{
	struct spwd *sp;
	struct termios term;
	char user[SDM_MAXPW];
	char passwd[SDM_MAXPW];
	char *hash;
	int c, i;

	fputs("Username: ", stdout);
	i = 0;
	while((c = getchar()) != '\n' && c != EOF && i < SDM_MAXPW - 1) {
		user[i++] = c;
	}
	user[i] = '\0';
	fputs("Password: ", stdout);
	i = 0;
	/* disable input echo */
	tcgetattr(STDIN_FILENO, &term);
	term.c_lflag &= ~ECHO;
	tcsetattr(STDIN_FILENO, 0, &term);
	while((c = getchar()) != '\n' && c != EOF && i < SDM_MAXPW - 1) {
		passwd[i++] = c;
	}
	passwd[i] = '\0';
	if ((sp = getspnam(user)) == NULL) {
		return NULL;
	}
	/* reenable input echo */
	term.c_lflag |= ECHO;
	tcsetattr(STDIN_FILENO, 0, &term);
	/* hash inputed password and compare against shadow file entry */
	hash = crypt(passwd, sp->sp_pwdp);
	if (strcmp(hash, sp->sp_pwdp)) {
		fputs("Incorrect\n", stdout);
		return NULL;
	} else {
		fputs("Correct\n", stdout);
		return getpwnam(user);
	}
}

/* set env variables and run X
 */
static int
runsession(struct passwd *pw, char vtn) {
	char vtarg[] = "vt1";
	int status;
	pid_t shpid, Xpid;

	vtarg[2] = vtn;
	setuid(pw->pw_uid);
	setenv("SHELL", pw->pw_shell, 1);
	setenv("HOME", pw->pw_dir, 1);
	setenv("DISPLAY", SDM_DISPLAY, 1);
	chdir(pw->pw_dir);
	if ((Xpid = fork()) == 0) {
		execl("/bin/Xorg", "/bin/Xorg", SDM_DISPLAY, vtarg, (char *) NULL);
		return -1;
	} else if (Xpid < 0) {
		return -1;
	}
	sleep(2);
	if ((shpid = fork()) == 0) {
		execl(pw->pw_shell, pw->pw_shell, "--login", "-c", SDM_WM, (char *) NULL);
		return -1;
	} else if (shpid < 0) {
		return -1;
	}
	wait(&status);
	kill(shpid, SIGTERM);
	kill(Xpid, SIGTERM);
	exit(EXIT_SUCCESS);
}

int
main(int argc, char *argv[])
{
	struct passwd *pw;
	int fd, status;
	pid_t pid;

	if (argc < 2) {
		goto error;
	}
	if (strstr(argv[1], "/dev/tty") != argv[1] || !isdigit(argv[1][8])) {
		goto error;
	}
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
		if ((pid = fork()) == 0) {
			runsession(pw, argv[1][8]);
		} else if (pid < 0) {
			goto error;
		}
		waitpid(pid, &status, 0);
		sleep(2);
		system("/bin/clear");
		continue;
	}
	if (runsession(pw, argv[1][8])) {
		goto error;
	}
error:
	close(fd);
	exit(EXIT_FAILURE);
}
