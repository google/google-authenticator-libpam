#ifndef AUTHY_H
#define AUTHY_H

typedef enum {
	AUTHY_OK = 0,
	AUTHY_LIB_ERROR,
	AUTHY_CONN_ERROR,
	AUTHY_APPROVED,
	AUTHY_DENIED,
	AUTHY_PENDING,
	AUTHY_EXPIRED,
} authy_rc_t;

authy_rc_t authy_login(pam_handle_t *pamh, long authy_id, char *api_key, int timeout);

#endif /* AUTHY_H */
