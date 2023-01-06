#include <crypt.h>
#include <ctype.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <pwd.h>
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#define SDM_MAXPW 256

static void clear();
static int getty(char *path);
static char *gethash(struct passwd *pw);
static struct passwd *getpw();
static int runsession(struct passwd *pw, char *vtarg);

static void
clear()
{
	system("/bin/clear");
}

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

static char *
gethash(struct passwd *pw)
{
	struct spwd *sp;
	char *hash;

	hash = pw->pw_passwd;
	if (!strcmp(hash, "x")) {
		if ((sp = getspnam(pw->pw_name)) == NULL) {
			return NULL;
		}
		hash = sp->sp_pwdp;
	}

	return hash;
}

/* prompt user for username and password, and authenticate against shadow file
 */
static struct passwd *
getpw()
{
	struct passwd *pw;
	struct termios term;
	char user[SDM_MAXPW];
	char passwd[SDM_MAXPW];
	char *hash, *inputhash;
	int c, i;

	clear();
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
	/* reenable input echo */
	term.c_lflag |= ECHO;
	tcsetattr(STDIN_FILENO, 0, &term);
	/* hash inputed password and compare against shadow file entry */
	if ((pw = getpwnam(user)) == NULL) {
		return NULL;
	}
	hash = gethash(pw);
	inputhash = crypt(passwd, hash);
	if (strcmp(inputhash, hash)) {
		fputs("\nIncorrect\n", stdout);
		return NULL;
	} else {
		fputs("\nCorrect\n", stdout);
		return pw;
	}
}

/* set env variables and run X
 */
static int
runsession(struct passwd *pw, char *vtarg) {
	pid_t pid;

	setuid(pw->pw_uid);
	initgroups(pw->pw_name, pw->pw_gid);
	chdir(pw->pw_dir);
	setenv("HOME", pw->pw_dir, 1);
	setenv("SHELL", pw->pw_shell, 1);
	if ((pid = fork()) == 0) {
		execl(pw->pw_shell, pw->pw_shell, "--login", "-c", "/usr/bin/startx", (char *) NULL);
		return -1;
	} else if (pid < 0) {
		return -1;
	}
	wait(NULL);
	exit(EXIT_SUCCESS);
}

int
main(int argc, char *argv[])
{
	const struct option vtopt = {
		.name = "vt",
		.has_arg = 1,
		.flag = NULL,
		.val = 'v'
	};
	const char *optstring = "v:";
	struct passwd *pw;
	char ttypath[] = "/dev/tty7";
	char vtarg[] = "vt7";
	int fd, status;
	pid_t pid;

	switch (getopt_long(argc, argv, optstring, &vtopt, NULL)) {
		case 'v':
			if (isdigit(*optarg)) {
				ttypath[8] = *optarg;
				vtarg[2] = *optarg;
				break;
			}
		default:
			printf("Usage: %s --vt|-v [TTY NUMBER]\n", argv[0]);
			goto error;
	}
	pid = fork();
	if (pid > 0) {
		exit(EXIT_SUCCESS);
	} else if (pid < 0) {
		goto error;
	}
	if (setsid() < 0 || setgid(5) < 0) {
		goto error;
	}
	if ((fd = getty(ttypath)) < 0) {
		goto error;
	}
	while (1) {
		while(!(pw = getpw()));
		if (!pw) {
			goto error;
		}
		chown(ttypath, pw->pw_uid, pw->pw_gid);
		if ((pid = fork()) == 0) {
			runsession(pw, vtarg);
		} else if (pid < 0) {
			chown(ttypath, 0, 5);
			goto error;
		}
		waitpid(pid, &status, 0);
		chown(ttypath, 0, 5);
		sleep(2);
		continue;
	}
error:
	close(fd);
	exit(EXIT_FAILURE);
}
