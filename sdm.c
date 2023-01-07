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

static struct passwd *user_pw;
static char xinitcmd[256] = 
"/usr/bin/xinit ./.xinitrc -- /etc/X11/xinit/xserverrc ";
static char tty[11] = "/dev/tty\0\0";
static char vt[5] = "vt\0\0";
static char display[4] = ":1\0";
static int fd;

static int  handleargs(int argc, char *argv[]);
static int  getty();
static int  getuser();
static void runX();

static int handleargs(int argc, char *argv[]) {
	const struct option vtopt = {
		.name = "vt",
		.has_arg = 1,
		.flag = NULL,
		.val = 'v'
	};
	const char *optstring = "v:";
	int i;

	switch (getopt_long(argc, argv, optstring, &vtopt, NULL)) {
		case 'v':
			for (i = 0; optarg[i]; ++i) {
				if (!isdigit(optarg[i])) {
					return -1;
				}
			}
			strncpy(tty + 8, optarg, 2);
			strncpy(vt + 2, optarg, 2);
			return 0;
		default:
			return -1;
	}
}

/* open tty device at path and set stdin, stdout, and stderr
 */
static int
getty()
{
	if ((fd = open(tty, O_RDWR)) < 0) {
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

	return 0;
}

/* prompt user for username and password, and authenticate against shadow file
 */
static int 
getuser()
{
	struct spwd *sp;
	struct termios term;
	char user[SDM_MAXPW];
	char password[SDM_MAXPW];
	char *hash;
	int c, i;

	system("/usr/bin/clear");
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
		password[i++] = c;
	}
	password[i] = '\0';
	/* reenable input echo */
	term.c_lflag |= ECHO;
	tcsetattr(STDIN_FILENO, 0, &term);
	if ((user_pw = getpwnam(user)) == NULL) {
		return -1;
	}
	/* hash input with salt from stored hash */
	hash = user_pw->pw_passwd;
	if (!strcmp(hash, "x")) {
		if ((sp = getspnam(user_pw->pw_name)) == NULL) {
			return -1;
		}
		hash = sp->sp_pwdp;
	}
	if (strcmp(hash, crypt(password, hash))) {
		fputs("\nIncorrect\n", stdout);
		return -1;
	} else {
		fputs("\nCorrect\n", stdout);
		return 0;
	}
}

/* set env variables and run X
 */
static void
runX() {
	strcat(xinitcmd, display);
	strcat(xinitcmd, " ");
	strcat(xinitcmd, vt);
	strcat(xinitcmd, " -keeptty");
	setuid(user_pw->pw_uid);
	setgid(user_pw->pw_gid);
	initgroups(user_pw->pw_name, user_pw->pw_gid);
	chdir(user_pw->pw_dir);
	setenv("HOME", user_pw->pw_dir, 1);
	setenv("SHELL", user_pw->pw_shell, 1);
	setenv("DISPLAY", display, 1);
	execl(
			user_pw->pw_shell, user_pw->pw_shell,
			"--login", "-c", xinitcmd,
			(char *) NULL
		 );
}

int
main(int argc, char *argv[])
{
	pid_t pid;

	if (handleargs(argc, argv) < 0) {
		printf("Usage: %s --vt|-v [TTY NUMBER]\n", argv[0]);
	}
	if ((pid = fork()) > 0) {
		exit(EXIT_SUCCESS);
	} else if (pid < 0) {
		goto error;
	}
	if (setsid() < 0 || setgid(5) < 0) {
		goto error;
	}
	if (getty() < 0) {
		goto error;
	}
	while (1) {
		while (getuser() < 0);
		if ((pid = fork()) == 0) {
			runX();
		} else if (pid < 0) {
			goto error;
		}
		wait(NULL);
	}
error:
	close(fd);
	exit(EXIT_FAILURE);
}
