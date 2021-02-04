/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -std=gnu99 -Wall -g -o mylogin login_linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
#include "pwent.h"

#define TRUE 1
#define FALSE 0
#define LENGTH 16

void sighandler() {
	return; // Ignore signal
}

int main(int argc, char *argv[]) {
	// IGNORE ALL SIGNALS
	signal(SIGINT, &sighandler);
	signal(SIGTERM, &sighandler);
	signal(SIGQUIT, &sighandler);
	signal(SIGTSTP, &sighandler);

	mypwent *passwddata;

	static const char SALT[] = "as";

	char important1[LENGTH] = "**IMPORTANT 1**";

	char user[LENGTH];

	char important2[LENGTH] = "**IMPORTANT 2**";

	//char   *c_pass; //you might want to use this variable later...
	char prompt[] = "password: ";
	char *user_pass;

	sighandler();

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important1' before input of login name: %s\n",
				important1);
		printf("Value of variable 'important2' before input of login name: %s\n",
				important2);

		printf("login: ");
		fflush(NULL); 	 /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */

		if (fgets(user, LENGTH, stdin) == NULL) /* gets() is vulnerable to buffer, changed to fgets()*/
			exit(0); /*  overflow attacks.  */

		// remove '\n'
		user[strlen(user) - 1] = '\0';

		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important 1' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important1);
		printf("Value of variable 'important 2' after input of login name: %*.*s\n",
		 		LENGTH - 1, LENGTH - 1, important2);

		user_pass = getpass(prompt);        //gets input password from terminal
		passwddata = mygetpwnam(user);      //checks password for 'user' in /etc/passwd
																				//returns a pointer

		if (passwddata != NULL) {
			// Barrier against faulty password inputs
			if(passwddata->pwfailed >= 5){
				printf("Login Incorrect2 \n");
			}
			else{
				// Check if password is correct
				if (!strcmp(crypt(user_pass, SALT), passwddata->passwd)) {

					printf(" You're in !\n");
					printf("Failed attempts: %d \n", passwddata->pwfailed);
					passwddata->pwfailed = 0; // reset

					passwddata->pwage += 1; // increment

					mysetpwent(user, passwddata);

					// FORCE UPDATING PASSWORD
					if(passwddata->pwage > 10){
						printf("WARNING PASSWORD TOO OLD, CHANGE NOW!\n");

						// Get new pass
						char new_passwd[LENGTH];
						while(TRUE){
							const char* new_pass = getpass("New Password: ");
							const char* new_pass2 = getpass("Re-Enter New Password: ");
							if(strcmp(new_pass, new_pass2) == 0){
								strncpy(new_passwd, new_pass, LENGTH);
								break;
							}

							printf("Password do not match, try again");
						}

						// Update variables
						passwddata->passwd = crypt(new_passwd, SALT);
						passwddata->pwage = 0;

						mysetpwent(user, passwddata);

						printf("Password has successfully been changed");
					}

					// Check uid
					if(setuid(passwddata->uid) == -1){
						printf("Failed to set UID\n");
						continue;
					}
					else{
						// Start shell
						if(execve("/bin/sh", argv, NULL) == -1){
							return -1;
						}
					}
				}
				else{
					// Update if failed
					passwddata->pwfailed += 1; // increment

					mysetpwent(user, passwddata);

					printf("Login Incorrect \n");
				}
			}
		}
		else{
			printf("Login Incorrect \n");
		}

	}
	return 0;
}
