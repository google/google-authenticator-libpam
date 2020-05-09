#define _GNU_SOURCE

#include "config.h"
#include <stdio.h>
#include <unistd.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <jansson.h>
#include <curl/curl.h>

#include "pam_authy.h"

#if 0
typedef struct {
       char *memory;
       size_t size;
} mblock_t;

static size_t ctrl_curl_receive(void *content, size_t size, size_t nmemb,
		void *user_mem)
{
       size_t realsize = size * nmemb;
       mblock_t *mem = (mblock_t *)user_mem;

       mem->memory = realloc(mem->memory, mem->size + realsize + 1);
       if (mem->memory == NULL) {
              return -ENOMEM;
       }

       memcpy(&(mem->memory[mem->size]), content, realsize);
       mem->size += realsize;
       mem->memory[mem->size] = 0;

       return realsize;
}

static authy_rc_t authy_check_aproval(char *api_key, char *uuid)
{
	CURL *curl = NULL;
	CURLcode res;
	authy_rc_t rc;
	mblock_t buffer = {0};
	struct curl_slist *headers = NULL;
	char *url = NULL, *xheader = NULL, *str = NULL;
	json_t *payload = NULL, *jt = NULL;

	curl = curl_easy_init();
	if (!curl) {
		rc = AUTHY_CLIENT_ERROR;
		goto exit_err;
	}

	asprintf(&url, "https://api.authy.com/onetouch/json/approval_requests/%s",
			uuid);
	asprintf(&xheader, "X-Authy-API-Key: %s", api_key);
	headers = curl_slist_append(headers, xheader);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ctrl_curl_receive);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&buffer);

	res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform() failed: %s\n",
		curl_easy_strerror(res));
		rc = AUTHY_CONN_ERROR;
		goto exit_err;
	}
	rc = AUTHY_OK;

	payload = json_loads(buffer.memory, JSON_DECODE_ANY, NULL);
	jt = json_object_get(payload, "approval_request");
	if (!jt) {
		rc = AUTHY_CONN_ERROR;
		goto exit_err;
	}

	str = (char *)json_string_value(json_object_get(jt, "status"));
	if (!str) {
		rc = AUTHY_CONN_ERROR;
		goto exit_err;
	}

	if (!strcmp(str, "pending")) {
		rc = AUTHY_PENDING;
	} else if (!strcmp(str, "expired")) {
		rc = AUTHY_EXPIRED;
	} else if (!strcmp(str, "denied")) {
		rc = AUTHY_DENIED;
	} else if (!strcmp(str, "approved")) {
		rc = AUTHY_APPROVED;
	}

exit_err:
	if (buffer.memory)
		free(buffer.memory);

	if (jt)
		free(jt);

	if (str)
		free(str);

	if (payload)
		free(payload);

	if (url)
		free(url);

	if (curl)
		curl_easy_cleanup(curl);

	return rc;
}

static authy_rc_t authy_post_aproval(long authy_id, char *api_key, int timeout, char **uuid)
{
	CURL *curl = NULL;
	CURLcode res;
	authy_rc_t rc;
	mblock_t buffer = {0};
	struct curl_slist *headers = NULL;
	char *url = NULL, *xheader = NULL, *str = NULL;
	json_t *payload = NULL, *jt = NULL;

	curl = curl_easy_init();
	if (!curl) {
		rc = AUTHY_CLIENT_ERROR;
		goto exit_err;
	}

	asprintf(&url, "https://api.authy.com/onetouch/json/users/%ld/approval_requests",
			authy_id);
	asprintf(&xheader, "X-Authy-API-Key: %s", api_key);
	headers = curl_slist_append(headers, xheader);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ctrl_curl_receive);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&buffer);
	//curl_easy_setopt(curl, CURLOPT_POSTFIELDS, temp_string);

	res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform() failed: %s\n",
		curl_easy_strerror(res));
		rc = AUTHY_CONN_ERROR;
		goto exit_err;
	}
	rc = AUTHY_OK;

	payload = json_loads(buffer.memory, JSON_DECODE_ANY, NULL);

	jt = json_object_get(payload, "approval_request");
	if (!jt) {
		rc = AUTHY_CONN_ERROR;
		goto exit_err;
	}

	str = (char *)json_string_value(json_object_get(jt, "uuid"));
	if (!str) {
		rc = AUTHY_CONN_ERROR;
		goto exit_err;
	}
	asprintf(uuid, "%s", str);

exit_err:
	if (buffer.memory)
		free(buffer.memory);

	if (jt)
		free(jt);

	if (str)
		free(str);

	if (payload)
		free(payload);

	if (url)
		free(url);

	if (curl)
		curl_easy_cleanup(curl);

	return rc;
}

authy_rc_t authy_login(long authy_id, char *api_key, int timeout)
{
	time_t start_time;
	authy_rc_t rc;
	char *uuid = NULL;

	rc = authy_post_aproval(authy_id, api_key, 30, &uuid);
	if (rc != AUTHY_OK) {
		goto exit_err;
	}

	start_time = time(NULL);
	do {
		rc = authy_check_aproval(api_key, uuid);
		switch (rc) {
			case AUTHY_DENIED:
			case AUTHY_EXPIRED:
			case AUTHY_APPROVED:
				goto exit_err;
			default:
				break;
		}
		sleep(1);
	} while ((start_time + timeout) < time(NULL));
	rc = AUTHY_EXPIRED;

exit_err:
	if (uuid)
		free(uuid);

	return rc;
}
#endif
