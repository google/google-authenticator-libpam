#ifndef _PAM_UTIL_H_
#define _PAM_UTIL_H_

#define MODULE_NAME   "pam_google_authenticator"

void log_message(int priority, pam_handle_t *pamh,
                        const char *format, ...);

#endif /* _PAM_UTIL_H_ */
