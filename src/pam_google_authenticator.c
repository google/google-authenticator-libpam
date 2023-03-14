// PAM module for two-factor authentication.
//
// Copyright 2010 Google Inc.
// Author: Markus Gutschke
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#include "config.h"
#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h> /* struct hostent, gethostbyname */
#ifdef HAVE_SYS_FSUID_H
// We much rather prefer to use setfsuid(), but this function is unfortunately
// not available on all systems.
#include <sys/fsuid.h>
#endif

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#if !defined(LOG_AUTHPRIV) && defined(LOG_AUTH)
#define LOG_AUTHPRIV LOG_AUTH
#endif

#define PAM_SM_AUTH
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "base32.h"
#include "hmac.h"
#include "sha1.h"
#include "util.h"
#include <curl/curl.h>


// Module name shortened to work with rsyslog.
// See https://github.com/google/google-authenticator-libpam/issues/172
#define MODULE_NAME   "pam_google_auth"

#define SECRET        "~/.google_authenticator"
#define CODE_PROMPT   "Verification code: "
#define PWCODE_PROMPT "Password & verification code: "
#define LINE_BUFSIZE 128
typedef struct Params {
  const char *secret_filename_spec;
  const char *authtok_prompt;
  enum { NULLERR=0, NULLOK, SECRETNOTFOUND } nullok;
  int        noskewadj;
  int        echocode;
  int        fixed_uid;
  int        no_increment_hotp;
  uid_t      uid;
  enum { PROMPT = 0, TRY_FIRST_PASS, USE_FIRST_PASS } pass_mode;
  int        forward_pass;
  int        debug;
  int        no_strict_owner;
  int        allowed_perm;
  time_t     grace_period;
  int        allow_readonly;
} Params;

static char oom;

static const char* nobody = "nobody";

#if defined(DEMO) || defined(TESTING)
static char* error_msg = NULL;

const char *get_error_msg(void) __attribute__((visibility("default")));
const char *get_error_msg(void) {
  if (!error_msg) {
    return "";
  }
  return error_msg;
}
#endif

static void log_message(int priority, pam_handle_t *pamh,
                        const char *format, ...) {
  char *service = NULL;
  if (pamh)
    pam_get_item(pamh, PAM_SERVICE, (void *)&service);
  if (!service)
    service = "";

  char logname[80];
  snprintf(logname, sizeof(logname), "%s(" MODULE_NAME ")", service);

  va_list args;
  va_start(args, format);
#if !defined(DEMO) && !defined(TESTING)
  openlog(logname, LOG_CONS | LOG_PID, LOG_AUTHPRIV);
  vsyslog(priority, format, args);
  closelog();
#else
  if (!error_msg) {
    error_msg = strdup("");
  }
  {
    char buf[1000];
    vsnprintf(buf, sizeof buf, format, args);
    const int newlen = strlen(error_msg) + 1 + strlen(buf) + 1;
    char* n = malloc(newlen);
    if (n) {
      snprintf(n, newlen, "%s%s%s", error_msg, strlen(error_msg)?"\n":"",buf);
      free(error_msg);
      error_msg = n;
    } else {
      fprintf(stderr, "Failed to malloc %d bytes for log data.\n", newlen);
    }
  }
#endif

  va_end(args);

  if (priority == LOG_EMERG) {
    // Something really bad happened. There is no way we can proceed safely.
    _exit(1);
  }
}


#ifndef UNUSED_ATTR
# if __GNUC__ >= 3 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 7)
#  define UNUSED_ATTR __attribute__((__unused__))
# else
#  define UNUSED_ATTR
# endif
#endif

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags UNUSED_ATTR,
                                   int argc, const char **argv) {
  return google_authenticator(pamh, argc, argv);
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t *pamh UNUSED_ATTR,
                int flags UNUSED_ATTR,
                int argc UNUSED_ATTR,
                const char **argv UNUSED_ATTR) {
  return PAM_SUCCESS;
}

#ifdef PAM_STATIC
struct pam_module _pam_listfile_modstruct = {
  MODULE_NAME,
  pam_sm_authenticate,
  pam_sm_setcred,
  NULL,
  NULL,
  NULL,
  NULL
};
#endif
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */


int google_authenticator(pam_handle_t *pamh,
 		int argc, const char **argv) {
log_message(LOG_INFO,pamh,"Customized pam to invoke DID ");


char line[LINE_BUFSIZE];
    int linenr;
    FILE *output;
char *s;
    log_message(LOG_INFO,pamh,"Starting DID Assertion");
output = popen("/bin/sh /home/ubuntu/google_pam_test/google-authenticator-libpam/src/did.sh", "r");
    //  system("/bin/sh /home/ubuntu/google_pam_test/google-authenticator-libpam/src/did.sh > /home/ubuntu/out1.txt");
    /* Get a pipe where the output from the scripts comes in */
  //  pipe = popen("did.sh", "r");
if (output == NULL){
	log_message(LOG_INFO,pamh,"POPEN: Failed to execute");
}
else {
	int count =1;

while (fgets(line, LINE_BUFSIZE-1, output) != NULL)
    log_message(LOG_INFO,pamh,"Execution Result %s", line);
s = strstr(line,"\"isValid\"\:true");
if (s != NULL){
	log_message(LOG_INFO,pamh,"DID Authentication Successful !%d",s);
}else{
log_message(LOG_INFO,pamh,"No match, Authentication Failure");
//return PAM_AUTH_ERR;
}

}
pclose(output);

      log_message(LOG_INFO,pamh,"Do Authentication DID Complete, Pls check /home/user/out.log for output");
   // if (pipe == NULL) {  /* check for errors */
     //   log_message(LOG_INFO,pamh,"Pipe Null Err"); /* report error message */
        //return 1;        /* return with exit code indicating error 
    //}

    /* Read script output from the pipe line by line */
    //linenr = 1;
    /*while (fgets(line, LINE_BUFSIZE, pipe) != NULL) {
        log_message(LOG_INFO,pamh,"Script output line %d: %s", linenr, line);
        ++linenr;
    }*/
    
    /* Once here, out of the loop, the script has ended. */
    //pclose(pipe); /* Close the pipe 
//system("/home/ubuntu/google_pam_test/google-authenticator-libpam/src/did.sh");
//CURL *curl;
 // CURLcode res;
 
  /* In windows, this will init the winsock stuff */
//  curl_global_init(CURL_GLOBAL_ALL);
 
  /* get a curl handle */
 // curl = curl_easy_init();
  //if(curl) {
    /* First set the URL that is about to receive our POST. This URL can
       just as well be an https:// URL if that is what should receive the
       data. */
    /*curl_easy_setopt(curl, CURLOPT_URL, "https://auth0.service.authnull.com/authnull0/api/v1/authn/do-authentication");
    /* Now specify the POST data */
    /*curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "username=yy@gmail.com&responseType=ssh&endpoint=bijay&group=muthu");
 
    /* Perform the request, res will get the return code */
    /*res = curl_easy_perform(curl);
    /* Check for errors */
   /* if(res != CURLE_OK){
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));
    }else {
    printf("response from DID API", res);
    }
    /* always cleanup */
   /*curl_easy_cleanup(curl);
  }
  

 curl_global_cleanup();*/
 //
 //
     /* first what are we going to send and where are we going to send it? */
   /* int portno =        8080;
    char *host =        "https://auth0.service.authnull.com/authnull0/api/v1/authn/do-authentication";
    char *message_fmt = "POST /username=yy@gmail.com&responseType=ssh&endpoint=bijay&group=muthu HTTP/1.0\r\n\r\n";

    struct hostent *server;
    struct sockaddr_in serv_addr;
    int sockfd, bytes, sent, received, total;
    char message[1024],response[4096];

   // if (argc < 3) { puts("Parameters:  "); exit(0); }

    /* fill in the parameters */
   // sprintf(message,message_fmt,argv[1],argv[2]);
   // printf("Request:\n%s\n",message);

     /*create the socket */
    /*sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) log_message(LOG_INFO,pamh, "ERROR opening socket");

    /* lookup the ip address */
    /*server = gethostbyname(host);
    if (server == NULL) log_message(LOG_INFO, pamh,"ERROR, no such host");

    /* fill in the structure */
    /*memset(&serv_addr,0,sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(portno);
    memcpy(&serv_addr.sin_addr.s_addr,server->h_addr,server->h_length);

    /* connect the socket */
    /*if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0)
        log_message(LOG_ERR,pamh, "ERROR connecting");

    /* send the request */
    /*total = strlen(message);
    sent = 0;
    do {
        bytes = write(sockfd,message+sent,total-sent);
        if (bytes < 0)
            log_message(LOG_ERR,"ERROR writing message to socket","");
        if (bytes == 0)
            break;
        sent+=bytes;
    } while (sent < total);

    /* receive the response */
    /*memset(response,0,sizeof(response));
    total = sizeof(response)-1;
    received = 0;
    do {
        bytes = read(sockfd,response+received,total-received);
        if (bytes < 0)
            error("ERROR reading response from socket");
        if (bytes == 0)
            break;
        received+=bytes;
    } while (received < total);

    /*
     * if the number of received bytes is the total size of the
     * array then we have run out of space to store the response
     * and it hasn't all arrived yet - so that's a bad thing
     */
    /*if (received == total)
        error("ERROR storing complete response from socket");

    /* close the socket */
    //close(sockfd);

    /* process response */
    //printf("Response:\n%s\n",response);

    
return PAM_SUCCESS;
 }


