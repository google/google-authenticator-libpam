#ifndef AUTHY_H
#define AUTHY_H

typedef enum {
	AUTHY_CONTINUE = -1,	/* continue authentication */
	AUTHY_OK = 0,		/* great success! */
	AUTHY_FAIL,		/* nice try */
	AUTHY_ABORT,		/* give up */
	AUTHY_LIB_ERROR,	/* unexpected library error */
	AUTHY_CONN_ERROR,	/* problem connecting */
	AUTHY_CLIENT_ERROR,	/* you screwed up */
	AUTHY_SERVER_ERROR,	/* we screwed up */
	AUTHY_FAIL_SAFE_ALLOW,	/* preauth fails in failsafe mode */
	AUTHY_FAIL_SECURE_DENY,	/* preauth fails in failsecure mode */ 
	AUTHY_APPROVED,
	AUTHY_DENIED,
	AUTHY_PENDING,
	AUTHY_EXPIRED,
} authy_rc_t;

//authy_rc_t authy_login(long authy_id, char *api_key, int timeout);

#endif /* AUTHY_H */
