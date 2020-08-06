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

// Module name shortened to work with rsyslog.
// See https://github.com/google/google-authenticator-libpam/issues/172
#define MODULE_NAME   "pam_google_auth"

#define SECRET        "~/.google_authenticator"
#define CODE_PROMPT   "Verification code: "
#define PWCODE_PROMPT "Password & verification code: "

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

static int converse(pam_handle_t *pamh, int nargs,
                    PAM_CONST struct pam_message **message,
                    struct pam_response **response) {
  struct pam_conv *conv;
  int retval = pam_get_item(pamh, PAM_CONV, (void *)&conv);
  if (retval != PAM_SUCCESS) {
    return retval;
  }
  return conv->conv(nargs, message, response, conv->appdata_ptr);
}

static const char *get_user_name(pam_handle_t *pamh, const Params *params) {
  // Obtain the user's name
  const char *username;
  if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS ||
      !username || !*username) {
    log_message(LOG_ERR, pamh,
                "pam_get_user() failed to get a user name"
                " when checking verification code");
    return NULL;
  }
  if (params->debug) {
    log_message(LOG_INFO, pamh, "debug: start of google_authenticator for \"%s\"", username);
  }
  return username;
}

/*
 * Return rhost as a string. Return value must not be free()ed.
 * Returns NULL if PAM_RHOST is not known.
 */
static const char *
get_rhost(pam_handle_t *pamh, const Params *params) {
  // Get the remote host
  PAM_CONST void *rhost;
  if (pam_get_item(pamh, PAM_RHOST, &rhost) != PAM_SUCCESS) {
    log_message(LOG_ERR, pamh, "pam_get_rhost() failed to get the remote host");
    return NULL;
  }
  if (params->debug) {
    log_message(LOG_INFO, pamh, "debug: google_authenticator for host \"%s\"",
                rhost);
  }
  return (const char *)rhost;
}

static size_t
getpwnam_buf_max_size()
{
#ifdef _SC_GETPW_R_SIZE_MAX
  const ssize_t len = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (len <= 0) {
    return 4096;
  }
  return len;
#else
  return 4096;
#endif
}

static char *get_secret_filename(pam_handle_t *pamh, const Params *params,
                                 const char *username, uid_t *uid) {
  if (!username) {
    return NULL;
  }

  // Check whether the administrator decided to override the default location
  // for the secret file.
  const char *spec = params->secret_filename_spec
    ? params->secret_filename_spec : SECRET;

  // Obtain the user's id and home directory
  // NOTE: These variables need to be here because of their lifetimes.
  struct passwd *pw = NULL;     // Used
  struct passwd pwbuf;          // Here because `pw` points into it.
  char *buf = NULL;             // Here because `pw` members use it.
  char *secret_filename = NULL; // Here because goto jumps.

  if (!params->fixed_uid) {
    const int len = getpwnam_buf_max_size();
    buf = malloc(len);
    *uid = -1;
    if (buf == NULL) {
      log_message(LOG_ERR, pamh, "Short (%d) mem allocation failed", len);
      goto errout;
    }

    const int rc = getpwnam_r(username, &pwbuf, buf, len, &pw);
    if (rc) {
      log_message(LOG_ERR, pamh, "getpwnam_r(\"%s\")!=0: %d", username, rc);
      goto errout;
    }

    if (!pw) {
      log_message(LOG_ERR, pamh, "user(\"%s\") not found", username);
      goto errout;
    }

    if (!pw->pw_dir) {
      log_message(LOG_ERR, pamh, "user(\"%s\") has no home dir", username);
      goto errout;
    }

    if (*pw->pw_dir != '/') {
      log_message(LOG_ERR, pamh, "User \"%s\" home dir not absolute", username);
      goto errout;
    }
  }

  // Expand filename specification to an actual filename.
  if ((secret_filename = strdup(spec)) == NULL) {
    log_message(LOG_ERR, pamh, "Short (%d) mem allocation failed", strlen(spec));
    goto errout;
  }
  int allow_tilde = 1;
  for (int offset = 0; secret_filename[offset];) {
    char *cur = secret_filename + offset;
    char *var = NULL;
    size_t var_len = 0;
    const char *subst = NULL;
    if (allow_tilde && *cur == '~') {
      var_len = 1;
      if (!pw) {
        log_message(LOG_ERR, pamh,
                    "Home dir in 'secret' not implemented when 'user' set");
        goto errout;
      }
      subst = pw->pw_dir;
      var = cur;
    } else if (secret_filename[offset] == '$') {
      if (!memcmp(cur, "${HOME}", 7)) {
        var_len = 7;
        if (!pw) {
          log_message(LOG_ERR, pamh,
                      "Home dir in 'secret' not implemented when 'user' set");
          goto errout;
        }
        subst = pw->pw_dir;
        var = cur;
      } else if (!memcmp(cur, "${USER}", 7)) {
        var_len = 7;
        subst = username;
        var = cur;
      }
    }
    if (var) {
      const size_t subst_len = strlen(subst);
      if (subst_len > 1000000) {
        log_message(LOG_ERR, pamh, "Unexpectedly large path name: %d", subst_len);
        goto errout;
      }
      const int varidx = var - secret_filename;
      char *resized = realloc(secret_filename,
                              strlen(secret_filename) + subst_len + 1);
      if (!resized) {
        log_message(LOG_ERR, pamh, "Short mem allocation failed");
        goto errout;
      }
      var = resized + varidx;
      secret_filename = resized;
      memmove(var + subst_len, var + var_len, strlen(var + var_len) + 1);
      memmove(var, subst, subst_len);
      offset = var + subst_len - resized;
      allow_tilde = 0;
    } else {
      allow_tilde = *cur == '/';
      ++offset;
    }
  }

  *uid = params->fixed_uid ? params->uid : pw->pw_uid;
  free(buf);
  return secret_filename;

errout:
  free(secret_filename);
  free(buf);
  return NULL;
}

static int setuser(int uid) {
#ifdef HAVE_SETFSUID
  // The semantics for setfsuid() are a little unusual. On success, the
  // previous user id is returned. On failure, the current user id is returned.
  int old_uid = setfsuid(uid);
  if (uid != setfsuid(uid)) {
    setfsuid(old_uid);
    return -1;
  }
#else
#ifdef linux
#error "Linux should have setfsuid(). Refusing to build."
#endif
  int old_uid = geteuid();
  if (old_uid != uid && seteuid(uid)) {
    return -1;
  }
#endif
  return old_uid;
}

static int setgroup(int gid) {
#ifdef HAVE_SETFSGID
  // The semantics of setfsgid() are a little unusual. On success, the
  // previous group id is returned. On failure, the current groupd id is
  // returned.
  int old_gid = setfsgid(gid);
  if (gid != setfsgid(gid)) {
    setfsgid(old_gid);
    return -1;
  }
#else
  int old_gid = getegid();
  if (old_gid != gid && setegid(gid)) {
    return -1;
  }
#endif
  return old_gid;
}

// Drop privileges and return 0 on success.
static int drop_privileges(pam_handle_t *pamh, const char *username, int uid,
                           int *old_uid, int *old_gid) {
  // Try to become the new user. This might be necessary for NFS mounted home
  // directories.

  // First, look up the user's default group
  #ifdef _SC_GETPW_R_SIZE_MAX
  int len = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (len <= 0) {
    len = 4096;
  }
  #else
  int len = 4096;
  #endif
  char *buf = malloc(len);
  if (!buf) {
    log_message(LOG_ERR, pamh, "Out of memory");
    return -1;
  }
  struct passwd pwbuf, *pw;
  if (getpwuid_r(uid, &pwbuf, buf, len, &pw) || !pw) {
    log_message(LOG_ERR, pamh, "Cannot look up user id %d", uid);
    free(buf);
    return -1;
  }
  gid_t gid = pw->pw_gid;
  free(buf);

  int gid_o = setgroup(gid);
  int uid_o = setuser(uid);
  if (uid_o < 0) {
    if (gid_o >= 0) {
      if (setgroup(gid_o) < 0 || setgroup(gid_o) != gid_o) {
        // Inform the caller that we were unsuccessful in resetting the group.
        *old_gid = gid_o;
      }
    }
    log_message(LOG_ERR, pamh, "Failed to change user id to \"%s\"",
                username);
    return -1;
  }
  if (gid_o < 0 && (gid_o = setgroup(gid)) < 0) {
    // In most typical use cases, the PAM module will end up being called
    // while uid=0. This allows the module to change to an arbitrary group
    // prior to changing the uid. But there are many ways that PAM modules
    // can be invoked and in some scenarios this might not work. So, we also
    // try changing the group _after_ changing the uid. It might just work.
    if (setuser(uid_o) < 0 || setuser(uid_o) != uid_o) {
      // Inform the caller that we were unsuccessful in resetting the uid.
      *old_uid = uid_o;
    }
    log_message(LOG_ERR, pamh,
                "Failed to change group id for user \"%s\" to %d", username,
                (int)gid);
    return -1;
  }

  *old_uid = uid_o;
  *old_gid = gid_o;
  return 0;
}

// open secret file, return 0 on success.
static int open_secret_file(pam_handle_t *pamh, const char *secret_filename,
                            struct Params *params, const char *username,
                            int uid, struct stat *orig_stat) {
  // Try to open "~/.google_authenticator"
  const int fd = open(secret_filename, O_RDONLY);
  if (fd < 0 ||
      fstat(fd, orig_stat) < 0) {
    if (params->nullok != NULLERR && errno == ENOENT) {
      // The user doesn't have a state file, but the administrator said
      // that this is OK. We still return an error from open_secret_file(),
      // but we remember that this was the result of a missing state file.
      params->nullok = SECRETNOTFOUND;
    } else {
      log_message(LOG_ERR, pamh, "Failed to read \"%s\" for \"%s\": %s",
                  secret_filename, username, strerror(errno));
    }
 error:
    if (fd >= 0) {
      close(fd);
    }
    return -1;
  }

  if (params->debug) {
    log_message(LOG_INFO, pamh,
                "debug: Secret file permissions are %04o."
                " Allowed permissions are %04o",
                orig_stat->st_mode & 03777, params->allowed_perm);
  }

  // Check permissions on "~/.google_authenticator".
  if (!S_ISREG(orig_stat->st_mode)) {
    log_message(LOG_ERR, pamh, "Secret file \"%s\" is not a regular file",
                secret_filename);
    goto error;
  }
  if (orig_stat->st_mode & 03777 & ~params->allowed_perm) {
    log_message(LOG_ERR, pamh,
                "Secret file \"%s\" permissions (%04o)"
                " are more permissive than %04o", secret_filename,
                orig_stat->st_mode & 03777, params->allowed_perm);
    goto error;
  }

  if (!params->no_strict_owner && (orig_stat->st_uid != (uid_t)uid)) {
    char buf[80];
    if (params->fixed_uid) {
      snprintf(buf, sizeof buf, "user id %d", params->uid);
      username = buf;
    }
    log_message(LOG_ERR, pamh,
                "Secret file \"%s\" must be owned by \"%s\"",
                secret_filename, username);
    goto error;
  }

  // Sanity check for file length
  if (orig_stat->st_size < 1 || orig_stat->st_size > 64*1024) {
    log_message(LOG_ERR, pamh,
                "Invalid file size for \"%s\"", secret_filename);
    goto error;
  }

  return fd;
}

// Read secret file contents.
// If there's an error the file is closed, NULL is returned, and errno set.
static char *read_file_contents(pam_handle_t *pamh,
                                const Params *params,
                                const char *secret_filename, int *fd,
                                off_t filesize) {
  // Arbitrary limit to prevent integer overflow.
  if (filesize > 1000000) {
    close(*fd);
    errno = E2BIG;
    return NULL;
  }

  // Read file contents
  char *buf = malloc(filesize + 1);
  if (!buf) {
    log_message(LOG_ERR, pamh, "Failed to malloc %d+1", filesize);
    goto out;
  }

  if (filesize != read(*fd, buf, filesize)) {
    log_message(LOG_ERR, pamh, "Could not read \"%s\"", secret_filename);
    goto out;
  }
  close(*fd);
  *fd = -1;

  // The rest of the code assumes that there are no NUL bytes in the file.
  if (memchr(buf, 0, filesize)) {
    log_message(LOG_ERR, pamh, "Invalid file contents in \"%s\"",
                secret_filename);
    goto out;
  }

  // Terminate the buffer with a NUL byte.
  buf[filesize] = '\000';

  if(params->debug) {
    log_message(LOG_INFO, pamh, "debug: \"%s\" read", secret_filename);
  }
  return buf;

out:
  // If we have any data, erase it.
  if (buf) {
    explicit_bzero(buf, filesize);
  }
  free(buf);
  if (*fd >= 0) {
    close(*fd);
    *fd = -1;
  }
  return NULL;
}

static int is_totp(const char *buf) {
  return !!strstr(buf, "\" TOTP_AUTH");
}

// Wrap write() making sure that partial writes don't break everything.
// Return 0 on success, errno otherwise.
static int
full_write(int fd, const char* buf, size_t len) {
  const char* p = buf;
  int errors = 0;
  for (;;) {
    const ssize_t left = len - (p - buf);
    const ssize_t rc = write(fd, p, left);
    if (rc == left) {
      return 0;
    }
    if (rc < 0) {
      switch (errno) {
      case EAGAIN:
      case EINTR:
        if (errors++ < 3) {
          continue;
        }
      }
      return errno;
    }
    p += rc;
  }
}

// Safely overwrite the old secret file.
// Return 0 on success, errno otherwise.
static int write_file_contents(pam_handle_t *pamh,
                               const Params *params,
                               const char *secret_filename,
                               struct stat *orig_stat,
                               const char *buf) {
  int err = 0;
  int fd = -1;
  const size_t fnlength = strlen(secret_filename) + 1 + 6 + 1;

  char *tmp_filename = malloc(fnlength);
  if (tmp_filename == NULL) {
    err = errno;
    goto cleanup;
  }

  if (fnlength - 1 != snprintf(tmp_filename, fnlength,
                               "%s~XXXXXX", secret_filename)) {
    err = ERANGE;
    goto cleanup;
  }
  const mode_t old_mask = umask(077);
  fd = mkstemp(tmp_filename);
  umask(old_mask);
  if (fd < 0) {
    err = errno;
    log_message(LOG_ERR, pamh, "Failed to create tempfile \"%s\": %s",
                tmp_filename, strerror(err));

    // Couldn't open file; don't try to delete it later.
    free(tmp_filename);
    tmp_filename = NULL;
    goto cleanup;
  }
  if (fchmod(fd, 0400)) {
    err = errno;
    goto cleanup;
  }

  // Make sure the secret file is still the same. This prevents attackers
  // from opening a lot of pending sessions and then reusing the same
  // scratch code multiple times.
  //
  // (except for the brief race condition between this stat and the
  // `rename` below)
  {
    struct stat sb;
    if (stat(secret_filename, &sb) != 0) {
      err = errno;
      log_message(LOG_ERR, pamh, "stat(): %s", strerror(err));
      goto cleanup;
    }

    if (sb.st_ino != orig_stat->st_ino ||
        sb.st_size != orig_stat->st_size ||
        sb.st_mtime != orig_stat->st_mtime) {
      err = EAGAIN;
      log_message(LOG_ERR, pamh,
                  "Secret file \"%s\" changed while trying to use "
                  "scratch code\n", secret_filename);
      goto cleanup;
    }
  }

  // Write the new file contents.
  if ((err = full_write(fd, buf, strlen(buf)))) {
    log_message(LOG_ERR, pamh, "write(): %s", strerror(err));
    goto cleanup;
  }
  if (fsync(fd)) {
    err = errno;
    log_message(LOG_ERR, pamh, "fsync(): %s", strerror(err));
    goto cleanup;
  }
  if (close(fd)) {
    err = errno;
    log_message(LOG_ERR, pamh, "close(): %s", strerror(err));
    goto cleanup;
  }
  fd = -1; // Prevent double-close.

  // Double-check that the file size is correct.
  {
    struct stat st;
    if (stat(tmp_filename, &st)) {
      err = errno;
      log_message(LOG_ERR, pamh, "stat(%s): %s", tmp_filename, strerror(err));
      goto cleanup;
    }
    const off_t want = strlen(buf);
    if (st.st_size == 0 || (want != st.st_size)) {
      err = EAGAIN;
      log_message(LOG_ERR, pamh, "temp file size %d. Should be non-zero and %d", st.st_size, want);
      goto cleanup;
    }
  }
  
  if (rename(tmp_filename, secret_filename) != 0) {
    err = errno;
    log_message(LOG_ERR, pamh, "rename(): %s", strerror(err));
    goto cleanup;
  }
  free(tmp_filename);
  tmp_filename = NULL; // Prevent unlink & double-free.

  if (params->debug) {
    log_message(LOG_INFO, pamh, "debug: \"%s\" written", secret_filename);
  }

cleanup:
  if (fd >= 0) {
    close(fd);
  }
  if (tmp_filename) {
    if (unlink(tmp_filename)) {
      log_message(LOG_ERR, pamh, "Failed to delete tempfile \"%s\": %s",
                  tmp_filename, strerror(errno));
    }
  }
  free(tmp_filename);

  if (err) {
    log_message(LOG_ERR, pamh, "Failed to update secret file \"%s\": %s",
                secret_filename, strerror(err));
    return err;
  }
  return 0;
}

// given secret file content (buf), extract the secret and base32 decode it.
//
// Return pointer to `malloc()`'d secret on success (caller frees),
// NULL on error. Length of secret stored in *secretLen.
static uint8_t *get_shared_secret(pam_handle_t *pamh,
                                  const Params *params,
                                  const char *secret_filename,
                                  const char *buf, int *secretLen) {
  if (!buf) {
    return NULL;
  }
  // Decode secret key
  const int base32Len = strcspn(buf, "\n");

  // Arbitrary limit to prevent integer overflow.
  if (base32Len > 100000) {
    return NULL;
  }

  *secretLen = (base32Len*5 + 7)/8;
  uint8_t *secret = malloc(base32Len + 1);
  if (secret == NULL) {
    *secretLen = 0;
    return NULL;
  }
  memcpy(secret, buf, base32Len);
  secret[base32Len] = '\000';
  if ((*secretLen = base32_decode(secret, secret, base32Len)) < 1) {
    log_message(LOG_ERR, pamh,
                "Could not find a valid BASE32 encoded secret in \"%s\"",
                secret_filename);
    explicit_bzero(secret, base32Len);
    free(secret);
    return NULL;
  }
  memset(secret + *secretLen, 0, base32Len + 1 - *secretLen);

  if(params->debug) {
    log_message(LOG_INFO, pamh, "debug: shared secret in \"%s\" processed", secret_filename);
  }
  return secret;
}

#ifdef TESTING
static time_t current_time;
void set_time(time_t t) __attribute__((visibility("default")));
void set_time(time_t t) {
  current_time = t;
}

static time_t get_time(void) {
  return current_time;
}
#else
static time_t get_time(void) {
  return time(NULL);
}
#endif

static int comparator(const void *a, const void *b) {
  return *(unsigned int *)a - *(unsigned int *)b;
}

static char *get_cfg_value(pam_handle_t *pamh, const char *key,
                           const char *buf) {
  const size_t key_len = strlen(key);
  for (const char *line = buf; *line; ) {
    const char *ptr;
    if (line[0] == '"' && line[1] == ' ' && !strncmp(line+2, key, key_len) &&
        (!*(ptr = line+2+key_len) || *ptr == ' ' || *ptr == '\t' ||
         *ptr == '\r' || *ptr == '\n')) {
      ptr += strspn(ptr, " \t");
      size_t val_len = strcspn(ptr, "\r\n");
      char *val = malloc(val_len + 1);
      if (!val) {
        log_message(LOG_ERR, pamh, "Out of memory");
        return &oom;
      } else {
        memcpy(val, ptr, val_len);
        val[val_len] = '\000';
        return val;
      }
    } else {
      line += strcspn(line, "\r\n");
      line += strspn(line, "\r\n");
    }
  }
  return NULL;
}

static int set_cfg_value(pam_handle_t *pamh, const char *key, const char *val,
                         char **buf) {
  const size_t key_len = strlen(key);
  char *start = NULL;
  char *stop = NULL;

  // Find an existing line, if any.
  for (char *line = *buf; *line; ) {
    char *ptr;
    if (line[0] == '"' && line[1] == ' ' && !strncmp(line+2, key, key_len) &&
        (!*(ptr = line+2+key_len) || *ptr == ' ' || *ptr == '\t' ||
         *ptr == '\r' || *ptr == '\n')) {
      start = line;
      stop  = start + strcspn(start, "\r\n");
      stop += strspn(stop, "\r\n");
      break;
    } else {
      line += strcspn(line, "\r\n");
      line += strspn(line, "\r\n");
    }
  }

  // If no existing line, insert immediately after the first line.
  if (!start) {
    start  = *buf + strcspn(*buf, "\r\n");
    start += strspn(start, "\r\n");
    stop   = start;
  }

  // Replace [start..stop] with the new contents.
  const size_t val_len = strlen(val);
  const size_t total_len = key_len + val_len + 4;
  if (total_len <= stop - start) {
    // We are decreasing out space requirements. Shrink the buffer and pad with
    // NUL characters.
    const size_t tail_len = strlen(stop);
    memmove(start + total_len, stop, tail_len + 1);
    memset(start + total_len + tail_len, 0, stop - start - total_len + 1);
  } else {
    // Must resize existing buffer. We cannot call realloc(), as it could
    // leave parts of the buffer content in unused parts of the heap.
    const size_t buf_len = strlen(*buf);
    const size_t tail_len = buf_len - (stop - *buf);
    char *resized = malloc(buf_len - (stop - start) + total_len + 1);
    if (!resized) {
      log_message(LOG_ERR, pamh, "Out of memory");
      return -1;
    }
    memcpy(resized, *buf, start - *buf);
    memcpy(resized + (start - *buf) + total_len, stop, tail_len + 1);
    memset(*buf, 0, buf_len);
    free(*buf);
    start = start - *buf + resized;
    *buf = resized;
  }

  // Fill in new contents.
  start[0] = '"';
  start[1] = ' ';
  memcpy(start + 2, key, key_len);
  start[2+key_len] = ' ';
  memcpy(start+3+key_len, val, val_len);
  start[3+key_len+val_len] = '\n';

  // Check if there are any other occurrences of "value". If so, delete them.
  for (char *line = start + 4 + key_len + val_len; *line; ) {
    char *ptr;
    if (line[0] == '"' && line[1] == ' ' && !strncmp(line+2, key, key_len) &&
        (!*(ptr = line+2+key_len) || *ptr == ' ' || *ptr == '\t' ||
         *ptr == '\r' || *ptr == '\n')) {
      start = line;
      stop = start + strcspn(start, "\r\n");
      stop += strspn(stop, "\r\n");
      size_t tail_len = strlen(stop);
      memmove(start, stop, tail_len + 1);
      memset(start + tail_len, 0, stop - start);
      line = start;
    } else {
      line += strcspn(line, "\r\n");
      line += strspn(line, "\r\n");
    }
  }

  return 0;
}

static int step_size(pam_handle_t *pamh, const char *secret_filename,
                     const char *buf) {
  const char *value = get_cfg_value(pamh, "STEP_SIZE", buf);
  if (!value) {
    // Default step size is 30.
    return 30;
  } else if (value == &oom) {
    // Out of memory. This is a fatal error.
    return 0;
  }

  char *endptr;
  errno = 0;
  const int step = (int)strtoul(value, &endptr, 10);
  if (errno || !*value || value == endptr ||
      (*endptr && *endptr != ' ' && *endptr != '\t' &&
       *endptr != '\n' && *endptr != '\r') ||
      step < 1 || step > 60) {
    free((void *)value);
    log_message(LOG_ERR, pamh, "Invalid STEP_SIZE option in \"%s\"",
                secret_filename);
    return 0;
  }
  free((void *)value);
  return step;
}

static int get_timestamp(pam_handle_t *pamh, const char *secret_filename,
                         const char **buf) {
  const int step = step_size(pamh, secret_filename, *buf);
  if (!step) {
    return 0;
  }
  return get_time()/step;
}

static long get_hotp_counter(pam_handle_t *pamh, const char *buf) {
  if (!buf) {
    return -1;
  }
  const char *counter_str = get_cfg_value(pamh, "HOTP_COUNTER", buf);
  if (counter_str == &oom) {
    // Out of memory. This is a fatal error
    return -1;
  }

  long counter = 0;
  if (counter_str) {
    counter = strtol(counter_str, NULL, 10);
  }
  free((void *)counter_str);

  return counter;
}

static int rate_limit(pam_handle_t *pamh, const char *secret_filename,
                      int *updated, char **buf) {
  const char *value = get_cfg_value(pamh, "RATE_LIMIT", *buf);
  if (!value) {
    // Rate limiting is not enabled for this account
    return 0;
  } else if (value == &oom) {
    // Out of memory. This is a fatal error.
    return -1;
  }

  // Parse both the maximum number of login attempts and the time interval
  // that we are looking at.
  const char *endptr = value, *ptr;
  int attempts, interval;
  errno = 0;
  if (((attempts = (int)strtoul(ptr = endptr, (char **)&endptr, 10)) < 1) ||
      ptr == endptr ||
      attempts > 100 ||
      errno ||
      (*endptr != ' ' && *endptr != '\t') ||
      ((interval = (int)strtoul(ptr = endptr, (char **)&endptr, 10)) < 1) ||
      ptr == endptr ||
      interval > 3600 ||
      errno) {
    free((void *)value);
    log_message(LOG_ERR, pamh, "Invalid RATE_LIMIT option. Check \"%s\".",
                secret_filename);
    return -1;
  }

  // Parse the time stamps of all previous login attempts.
  const unsigned int now = get_time();
  unsigned int *timestamps = malloc(sizeof(int));
  if (!timestamps) {
  oom:
    free((void *)value);
    log_message(LOG_ERR, pamh, "Out of memory");
    return -1;
  }
  timestamps[0] = now;
  int num_timestamps = 1;
  while (*endptr && *endptr != '\r' && *endptr != '\n') {
    unsigned int timestamp;
    errno = 0;
    if ((*endptr != ' ' && *endptr != '\t') ||
        ((timestamp = (int)strtoul(ptr = endptr, (char **)&endptr, 10)),
         errno) ||
        ptr == endptr) {
      free((void *)value);
      free(timestamps);
      log_message(LOG_ERR, pamh, "Invalid list of timestamps in RATE_LIMIT. "
                  "Check \"%s\".", secret_filename);
      return -1;
    }
    num_timestamps++;
    unsigned int *tmp = (unsigned int *)realloc(timestamps,
                                                sizeof(int) * num_timestamps);
    if (!tmp) {
      free(timestamps);
      goto oom;
    }
    timestamps = tmp;
    timestamps[num_timestamps-1] = timestamp;
  }
  free((void *)value);
  value = NULL;

  // Sort time stamps, then prune all entries outside of the current time
  // interval.
  qsort(timestamps, num_timestamps, sizeof(int), comparator);
  int start = 0, stop = -1;
  for (int i = 0; i < num_timestamps; ++i) {
    if (timestamps[i] < now - interval) {
      start = i+1;
    } else if (timestamps[i] > now) {
      break;
    }
    stop = i;
  }

  // Error out, if there are too many login attempts.
  int exceeded = 0;
  if (stop - start + 1 > attempts) {
    exceeded = 1;
    start = stop - attempts + 1;
  }

  // Construct new list of timestamps within the current time interval.
  char* list;
  {
    const size_t list_size = 25 * (2 + (stop - start + 1)) + 4;
    list = malloc(list_size);
    if (!list) {
      free(timestamps);
      goto oom;
    }
    snprintf(list, list_size, "%d %d", attempts, interval);
    char *prnt = strchr(list, '\000');
    for (int i = start; i <= stop; ++i) {
      prnt += snprintf(prnt, list_size-(prnt-list), " %u", timestamps[i]);
    }
    free(timestamps);
  }

  // Try to update RATE_LIMIT line.
  if (set_cfg_value(pamh, "RATE_LIMIT", list, buf) < 0) {
    free(list);
    return -1;
  }
  free(list);

  // Mark the state file as changed.
  *updated = 1;

  // If necessary, notify the user of the rate limiting that is in effect.
  if (exceeded) {
    log_message(LOG_ERR, pamh,
                "Too many concurrent login attempts (\"%s\"). Please try again.", secret_filename);
    return -1;
  }

  return 0;
}

static char *get_first_pass(pam_handle_t *pamh) {
  PAM_CONST void *password = NULL;
  if (pam_get_item(pamh, PAM_AUTHTOK, &password) == PAM_SUCCESS &&
      password) {
    return strdup((const char *)password);
  }
  return NULL;
}

// Show error message to the user.
static void
conv_error(pam_handle_t *pamh, const char* text) {
  PAM_CONST struct pam_message msg = {
    .msg_style = PAM_ERROR_MSG,
    .msg       = text,
  };
  PAM_CONST struct pam_message *msgs = &msg;
  struct pam_response *resp = NULL;
  const int retval = converse(pamh, 1, &msgs, &resp);
  if (retval != PAM_SUCCESS) {
    log_message(LOG_ERR, pamh, "Failed to inform user of error");
  }
  free(resp);
}

static char *request_pass(pam_handle_t *pamh, int echocode,
                          PAM_CONST char *prompt) {
  // Query user for verification code
  PAM_CONST struct pam_message msg = { .msg_style = echocode,
                                   .msg       = prompt };
  PAM_CONST struct pam_message *msgs = &msg;
  struct pam_response *resp = NULL;
  int retval = converse(pamh, 1, &msgs, &resp);
  char *ret = NULL;
  if (retval != PAM_SUCCESS || resp == NULL || resp->resp == NULL ||
      *resp->resp == '\000') {
    log_message(LOG_ERR, pamh, "Did not receive verification code from user");
    if (retval == PAM_SUCCESS && resp && resp->resp) {
      ret = resp->resp;
    }
  } else {
    ret = resp->resp;
  }

  // Deallocate temporary storage
  if (resp) {
    if (!ret) {
      free(resp->resp);
    }
    free(resp);
  }

  return ret;
}

/* Checks for possible use of scratch codes. Returns -1 on error, 0 on success,
 * and 1, if no scratch code had been entered, and subsequent tests should be
 * applied.
 */
static int check_scratch_codes(pam_handle_t *pamh,
                               const Params *params,
                               const char *secret_filename,
                               int *updated, char *buf, int code) {
  // Skip the first line. It contains the shared secret.
  char *ptr = buf + strcspn(buf, "\n");

  // Check if this is one of the scratch codes
  char *endptr = NULL;
  for (;;) {
    // Skip newlines and blank lines
    while (*ptr == '\r' || *ptr == '\n') {
      ptr++;
    }

    // Skip any lines starting with double-quotes. They contain option fields
    if (*ptr == '"') {
      ptr += strcspn(ptr, "\n");
      continue;
    }

    // Try to interpret the line as a scratch code
    errno = 0;
    const int scratchcode = (int)strtoul(ptr, &endptr, 10);

    // Sanity check that we read a valid scratch code. Scratchcodes are all
    // numeric eight-digit codes. There must not be any other information on
    // that line.
    if (errno ||
        ptr == endptr ||
        (*endptr != '\r' && *endptr != '\n' && *endptr) ||
        scratchcode  <  10*1000*1000 ||
        scratchcode >= 100*1000*1000) {
      break;
    }

    // Check if the code matches
    if (scratchcode == code) {
      // Remove scratch code after using it
      while (*endptr == '\n' || *endptr == '\r') {
        ++endptr;
      }
      memmove(ptr, endptr, strlen(endptr) + 1);
      memset(strrchr(ptr, '\000'), 0, endptr - ptr + 1);

      // Mark the state file as changed
      *updated = 1;

      // Successfully removed scratch code. Allow user to log in.
      if(params->debug) {
        log_message(LOG_INFO, pamh, "debug: scratch code %d used and removed from \"%s\"", code, secret_filename);
      }
      return 0;
    }
    ptr = endptr;
  }

  // No scratch code has been used. Continue checking other types of codes.
  if(params->debug) {
    log_message(LOG_INFO, pamh, "debug: no scratch code used from \"%s\"", secret_filename);
  }
  return 1;
}

static int window_size(pam_handle_t *pamh, const char *secret_filename,
                       const char *buf) {
  const char *value = get_cfg_value(pamh, "WINDOW_SIZE", buf);
  if (!value) {
    // Default window size is 3. This gives us one STEP_SIZE second
    // window before and after the current one.
    return 3;
  } else if (value == &oom) {
    // Out of memory. This is a fatal error.
    return 0;
  }

  char *endptr;
  errno = 0;
  const int window = (int)strtoul(value, &endptr, 10);
  if (errno || !*value || value == endptr ||
      (*endptr && *endptr != ' ' && *endptr != '\t' &&
       *endptr != '\n' && *endptr != '\r') ||
      window < 1 || window > 100) {
    free((void *)value);
    log_message(LOG_ERR, pamh, "Invalid WINDOW_SIZE option in \"%s\"",
                secret_filename);
    return 0;
  }
  free((void *)value);
  return window;
}

/* If the DISALLOW_REUSE option has been set, record timestamps have been
 * used to log in successfully and disallow their reuse.
 *
 * Returns -1 on error, and 0 on success.
 */
static int invalidate_timebased_code(int tm, pam_handle_t *pamh,
                                     const char *secret_filename,
                                     int *updated, char **buf) {
  char *disallow = get_cfg_value(pamh, "DISALLOW_REUSE", *buf);
  if (!disallow) {
    // Reuse of tokens is not explicitly disallowed. Allow the login request
    // to proceed.
    return 0;
  } else if (disallow == &oom) {
    // Out of memory. This is a fatal error.
    return -1;
  }

  // Allow the user to customize the window size parameter.
  const int window = window_size(pamh, secret_filename, *buf);
  if (!window) {
    // The user configured a non-standard window size, but there was some
    // error with the value of this parameter.
    free((void *)disallow);
    return -1;
  }

  // The DISALLOW_REUSE option is followed by all known timestamps that are
  // currently unavailable for login.
  for (char *ptr = disallow; *ptr;) {
    // Skip white-space, if any
    ptr += strspn(ptr, " \t\r\n");
    if (!*ptr) {
      break;
    }

    // Parse timestamp value.
    char *endptr;
    errno = 0;
    const int blocked = (int)strtoul(ptr, &endptr, 10);

    // Treat syntactically invalid options as an error
    if (errno ||
        ptr == endptr ||
        (*endptr != ' ' && *endptr != '\t' &&
         *endptr != '\r' && *endptr != '\n' && *endptr)) {
      free((void *)disallow);
      return -1;
    }

    if (tm == blocked) {
      // The code is currently blocked from use. Disallow login.
      free((void *)disallow);
      const int step = step_size(pamh, secret_filename, *buf);
      if (!step) {
        return -1;
      }
      log_message(LOG_ERR, pamh,
                  "Trying to reuse a previously used time-based code. (\"%s\")"
                  "Retry again in %d seconds. "
                  "Warning! This might mean, you are currently subject to a "
                  "man-in-the-middle attack.", secret_filename, step);
      return -1;
    }

    // If the blocked code is outside of the possible window of timestamps,
    // remove it from the file.
    if (blocked - tm >= window || tm - blocked >= window) {
      endptr += strspn(endptr, " \t");
      memmove(ptr, endptr, strlen(endptr) + 1);
    } else {
      ptr = endptr;
    }
  }

  // Add the current timestamp to the list of disallowed timestamps.
  {
    const size_t resized_size = strlen(disallow) + 40;
    char *resized = realloc(disallow, resized_size);
    if (!resized) {
      free((void *)disallow);
      log_message(LOG_ERR, pamh,
                  "Failed to allocate memory when updating \"%s\"",
                  secret_filename);
      return -1;
    }
    disallow = resized;
    char* pos = strrchr(disallow, '\000');
    snprintf(pos, resized_size-(pos-disallow), " %d" + !*disallow, tm);
    if (set_cfg_value(pamh, "DISALLOW_REUSE", disallow, buf) < 0) {
      free((void *)disallow);
      return -1;
    }
    free((void *)disallow);
  }

  // Mark the state file as changed
  *updated = 1;

  // Allow access.
  return 0;
}

/* Given an input value, this function computes the hash code that forms the
 * expected authentication token.
 */
#ifdef TESTING
int compute_code(const uint8_t *secret, int secretLen, unsigned long value)
  __attribute__((visibility("default")));
#else
static
#endif
int compute_code(const uint8_t *secret, int secretLen, unsigned long value) {
  uint8_t val[8];
  for (int i = 8; i--; value >>= 8) {
    val[i] = value;
  }
  uint8_t hash[SHA1_DIGEST_LENGTH];
  hmac_sha1(secret, secretLen, val, 8, hash, SHA1_DIGEST_LENGTH);
  explicit_bzero(val, sizeof(val));
  const int offset = hash[SHA1_DIGEST_LENGTH - 1] & 0xF;
  unsigned int truncatedHash = 0;
  for (int i = 0; i < 4; ++i) {
    truncatedHash <<= 8;
    truncatedHash  |= hash[offset + i];
  }
  explicit_bzero(hash, sizeof(hash));
  truncatedHash &= 0x7FFFFFFF;
  truncatedHash %= 1000000;
  return truncatedHash;
}

/* If a user repeated attempts to log in with the same time skew, remember
 * this skew factor for future login attempts.
 */
static int check_time_skew(pam_handle_t *pamh,
                           int *updated, char **buf, int skew, int tm) {
  int rc = -1;

  // Parse current RESETTING_TIME_SKEW line, if any.
  char *resetting = get_cfg_value(pamh, "RESETTING_TIME_SKEW", *buf);
  if (resetting == &oom) {
    // Out of memory. This is a fatal error.
    return -1;
  }

  // If the user can produce a sequence of three consecutive codes that fall
  // within a day of the current time. And if he can enter these codes in
  // quick succession, then we allow the time skew to be reset.
  // N.B. the number "3" was picked so that it would not trigger the rate
  // limiting limit if set up with default parameters.
  unsigned int tms[3];
  int skews[sizeof(tms)/sizeof(int)];

  int num_entries = 0;
  if (resetting) {
    char *ptr = resetting;

    // Read the three most recent pairs of time stamps and skew values into
    // our arrays.
    while (*ptr && *ptr != '\r' && *ptr != '\n') {
      char *endptr;
      errno = 0;
      const unsigned int i = (int)strtoul(ptr, &endptr, 10);
      if (errno || ptr == endptr || (*endptr != '+' && *endptr != '-')) {
        break;
      }
      ptr = endptr;
      int j = (int)strtoul(ptr + 1, &endptr, 10);
      if (errno ||
          ptr == endptr ||
          (*endptr != ' ' && *endptr != '\t' &&
           *endptr != '\r' && *endptr != '\n' && *endptr)) {
        break;
      }
      if (*ptr == '-') {
        j = -j;
      }
      if (num_entries == sizeof(tms)/sizeof(int)) {
        memmove(tms, tms+1, sizeof(tms)-sizeof(int));
        memmove(skews, skews+1, sizeof(skews)-sizeof(int));
      } else {
        ++num_entries;
      }
      tms[num_entries-1]   = i;
      skews[num_entries-1] = j;
      ptr = endptr;
    }

    // If the user entered an identical code, assume they are just getting
    // desperate. This doesn't actually provide us with any useful data,
    // though. Don't change any state and hope the user keeps trying a few
    // more times.
    if (num_entries &&
        tm + skew == tms[num_entries-1] + skews[num_entries-1]) {
      free((void *)resetting);
      return -1;
    }
  }
  free((void *)resetting);

  // Append new timestamp entry
  if (num_entries == sizeof(tms)/sizeof(int)) {
    memmove(tms, tms+1, sizeof(tms)-sizeof(int));
    memmove(skews, skews+1, sizeof(skews)-sizeof(int));
  } else {
    ++num_entries;
  }
  tms[num_entries-1]   = tm;
  skews[num_entries-1] = skew;

  // Check if we have the required amount of valid entries.
  if (num_entries == sizeof(tms)/sizeof(int)) {
    unsigned int last_tm = tms[0];
    int last_skew = skews[0];
    int avg_skew = last_skew;
    for (int i = 1; i < sizeof(tms)/sizeof(int); ++i) {
      // Check that we have a consecutive sequence of timestamps with no big
      // gaps in between. Also check that the time skew stays constant. Allow
      // a minor amount of fuzziness on all parameters.
      if (tms[i] <= last_tm || tms[i] > last_tm+2 ||
          last_skew - skew < -1 || last_skew - skew > 1) {
        goto keep_trying;
      }
      last_tm   = tms[i];
      last_skew = skews[i];
      avg_skew += last_skew;
    }
    avg_skew /= (int)(sizeof(tms)/sizeof(int));

    // The user entered the required number of valid codes in quick
    // succession. Establish a new valid time skew for all future login
    // attempts.
    char time_skew[40];
    snprintf(time_skew, sizeof time_skew, "%d", avg_skew);
    if (set_cfg_value(pamh, "TIME_SKEW", time_skew, buf) < 0) {
      return -1;
    }
    rc = 0;
  keep_trying:;
  }

  // Set the new RESETTING_TIME_SKEW line, while the user is still trying
  // to reset the time skew.
  {
    const size_t reset_size = 80 * (sizeof(tms)/sizeof(int));
    char reset[reset_size];
    *reset = '\000';
    if (rc) {
      for (int i = 0; i < num_entries; ++i) {
        char* pos = strrchr(reset, '\000');
        snprintf(pos, reset_size-(pos-reset), " %d%+d" + !*reset, tms[i], skews[i]);
      }
    }
    if (set_cfg_value(pamh, "RESETTING_TIME_SKEW", reset, buf) < 0) {
      return -1;
    }
  }

  // Mark the state file as changed
  *updated = 1;

  return rc;
}

/* Checks for time based verification code. Returns -1 on error, 0 on success,
 * and 1, if no time based code had been entered, and subsequent tests should
 * be applied.
 */
static int check_timebased_code(pam_handle_t *pamh, const char*secret_filename,
                                int *updated, char **buf, const uint8_t*secret,
                                int secretLen, int code, Params *params) {
  if (!is_totp(*buf)) {
    // The secret file does not actually contain information for a time-based
    // code. Return to caller and see if any other authentication methods
    // apply.
    return 1;
  }

  if (code < 0 || code >= 1000000) {
    // All time based verification codes are no longer than six digits.
    return 1;
  }

  // Compute verification codes and compare them with user input
  const int tm = get_timestamp(pamh, secret_filename, (const char **)buf);
  if (!tm) {
    return -1;
  }
  const char *skew_str = get_cfg_value(pamh, "TIME_SKEW", *buf);
  if (skew_str == &oom) {
    // Out of memory. This is a fatal error
    return -1;
  }

  int skew = 0;
  if (skew_str) {
    skew = (int)strtol(skew_str, NULL, 10);
  }
  free((void *)skew_str);

  const int window = window_size(pamh, secret_filename, *buf);
  if (!window) {
    return -1;
  }
  for (int i = -((window-1)/2); i <= window/2; ++i) {
    const unsigned int hash = compute_code(secret, secretLen, tm + skew + i);
    if (hash == (unsigned int)code) {
      return invalidate_timebased_code(tm + skew + i, pamh, secret_filename,
                                       updated, buf);
    }
  }

  if (!params->noskewadj) {
    // The most common failure mode is for the clocks to be insufficiently
    // synchronized. We can detect this and store a skew value for future
    // use.
    skew = 1000000;
    for (int i = 0; i < 25*60; ++i) {
      unsigned int hash = compute_code(secret, secretLen, tm - i);
      if (hash == (unsigned int)code && skew == 1000000) {
        // Don't short-circuit out of the loop as the obvious difference in
        // computation time could be a signal that is valuable to an attacker.
        skew = -i;
      }
      hash = compute_code(secret, secretLen, tm + i);
      if (hash == (unsigned int)code && skew == 1000000) {
        skew = i;
      }
    }
    if (skew != 1000000) {
      if(params->debug) {
        log_message(LOG_INFO, pamh, "debug: time skew adjusted");
      }
      return check_time_skew(pamh, updated, buf, skew, tm);
    }
  }

  return 1;
}

/*
 * Add a 'config' variable that says we logged in from a particular place
 * at a particular time. Only remembers the last 10 logins, which
 * are replaced in LRU order.
 *
 * Returns 0 on success.
 */
int
update_logindetails(pam_handle_t *pamh, const Params *params, char **buf) {
  const char *rhost = get_rhost(pamh, params);
  const time_t now = get_time();
  time_t oldest = now;    // Oldest entry seen so far.
  int oldest_index = -1;  // Index of oldest entry, due for replacement.
  int found = 0;          // Entry for this rhost found.
  char name[] = "LAST ";  // Config name template.

  if (rhost == NULL) {
    return -1;
  }

  for (int i = 0; i < 10; i++) {
    //
    // Get LAST<n> cfg value.
    //
    name[4] = i + '0';
    char *line = get_cfg_value(pamh, name, *buf);
    if (line == &oom) {
      /* Fatal! */
      return -1;
    }

    if (!line) {
      /* Make first empty line the oldest */
      if (oldest) {
        oldest_index = i;
        oldest = 0;
      }
      continue;
    }

    //
    // Parse value.
    //

    // Max len of ipv6 address is 8*4 digits plus 7 colons.
    // Plus trailing NUL is 40.
    // But RHOST can be FQDN, and by RFC1035 that's 255 characters as max.
    char host[256];
    unsigned long when = 0; // Timestamp of current entry.
    const int scanf_rc = sscanf(line, " %255[0-9a-zA-Z:.-] %lu ", host, &when);
    free(line);

    if (scanf_rc != 2) {
      log_message(LOG_ERR, pamh, "Malformed LAST%d line", i);
      continue;
    }

    if (!strcmp(host, rhost)) {
      found = 1;
      break;
    }

    if (when < oldest) {
      oldest_index = i;
      oldest = when;
    }
  }

  if (!found) {
    /* Loop completed all ten iterations */
    name[4] = oldest_index + '0';
  }

  /*
   * Max length in decimal digits of a 64 bit number is (64 log 2) + 1
   * Plus space and NUL termination, is 23.
   * Max len of hostname is 255.
   */
  char value[255+23+1];
  memset(value, 0, sizeof value);

  snprintf(value, sizeof value, "%s %lu", rhost, (unsigned long)now);
  if (set_cfg_value(pamh, name, value, buf) < 0) {
    log_message(LOG_WARNING, pamh, "Failed to set cfg value for login host");
  }

  return 0;
}

/*
 * Return non-zero if the last login from the same host as this one was
 * successfully authenticated within the grace period.
 */
int
within_grace_period(pam_handle_t *pamh, const Params *params,
                    const char *buf) {
  const char *rhost = get_rhost(pamh, params);
  const time_t now = get_time();
  const time_t grace = params->grace_period;
  unsigned long when = 0;
  char match[128];

  if (rhost == NULL) {
    return 0;
  }
  snprintf(match, sizeof match, " %s %%lu ", rhost);

  for (int i = 0; i < 10; i++) {
    static char name[] = "LAST0";
    name[4] = i + '0';
    char* line = get_cfg_value(pamh, name, buf);

    if (line == &oom) {
      /* Fatal! */
      return 0;
    }
    if (!line) {
      continue;
    }
    if (sscanf(line, match, &when) == 1) {
      free(line);
      break;
    }
    free(line);
  }

  if (when == 0) {
    /* No match */
    return 0;
  }

  return (when + grace > now);
}

/* Checks for counter based verification code. Returns -1 on error, 0 on
 * success, and 1, if no counter based code had been entered, and subsequent
 * tests should be applied.
 */
static int check_counterbased_code(pam_handle_t *pamh,
                                   const char*secret_filename, int *updated,
                                   char **buf, const uint8_t*secret,
                                   int secretLen, int code,
                                   long hotp_counter,
                                   int *must_advance_counter) {
  if (hotp_counter < 1) {
    // The secret file did not actually contain information for a counter-based
    // code. Return to caller and see if any other authentication methods
    // apply.
    return 1;
  }

  if (code < 0 || code >= 1000000) {
    // All counter based verification codes are no longer than six digits.
    return 1;
  }

  // Compute [window_size] verification codes and compare them with user input.
  // Future codes are allowed in case the user computed but did not use a code.
  const int window = window_size(pamh, secret_filename, *buf);
  if (!window) {
    return -1;
  }
  for (int i = 0; i < window; ++i) {
    const unsigned int hash = compute_code(secret, secretLen, hotp_counter + i);
    if (hash == (unsigned int)code) {
      char counter_str[40];
      snprintf(counter_str, sizeof counter_str, "%ld", hotp_counter + i + 1);
      if (set_cfg_value(pamh, "HOTP_COUNTER", counter_str, buf) < 0) {
        return -1;
      }
      *updated = 1;
      *must_advance_counter = 0;
      return 0;
    }
  }

  *must_advance_counter = 1;
  return 1;
}

// parse a user name.
// input: user name
// output: uid
// return: 0 on success.
static int parse_user(pam_handle_t *pamh, const char *name, uid_t *uid) {
  char *endptr;
  errno = 0;
  const long l = strtol(name, &endptr, 10);
  if (!errno && endptr != name && l >= 0 && l <= INT_MAX) {
    *uid = (uid_t)l;
    return 0;
  }
  const size_t len = getpwnam_buf_max_size();
  char *buf = malloc(len);
  if (!buf) {
    log_message(LOG_ERR, pamh, "Out of memory");
    return -1;
  }
  struct passwd pwbuf, *pw;
  if (getpwnam_r(name, &pwbuf, buf, len, &pw) || !pw) {
    free(buf);
    log_message(LOG_ERR, pamh, "Failed to look up user \"%s\"", name);
    return -1;
  }
  *uid = pw->pw_uid;
  free(buf);
  return 0;
}

static int parse_args(pam_handle_t *pamh, int argc, const char **argv,
                      Params *params) {
  params->debug = 0;
  params->echocode = PAM_PROMPT_ECHO_OFF;
  for (int i = 0; i < argc; ++i) {
    if (!strncmp(argv[i], "secret=", 7)) {
      params->secret_filename_spec = argv[i] + 7;
    } else if (!strncmp(argv[i], "authtok_prompt=", 15)) {
      params->authtok_prompt = argv[i] + 15;
    } else if (!strncmp(argv[i], "user=", 5)) {
      uid_t uid;
      if (parse_user(pamh, argv[i] + 5, &uid) < 0) {
        return -1;
      }
      params->fixed_uid = 1;
      params->uid = uid;
    } else if (!strncmp(argv[i], "allowed_perm=", 13)) {
      char *remainder = NULL;
      const int perm = (int)strtol(argv[i] + 13, &remainder, 8);
      if (perm == 0 || strlen(remainder) != 0) {
        log_message(LOG_ERR, pamh,
                    "Invalid permissions in setting \"%s\"."
                    " allowed_perm setting must be a positive octal integer.",
                    argv[i]);
        return -1;
      }
      params->allowed_perm = perm;
    } else if (!strcmp(argv[i], "no_strict_owner")) {
      params->no_strict_owner = 1;
    } else if (!strcmp(argv[i], "debug")) {
      params->debug = 1;
    } else if (!strcmp(argv[i], "try_first_pass")) {
      params->pass_mode = TRY_FIRST_PASS;
    } else if (!strcmp(argv[i], "use_first_pass")) {
      params->pass_mode = USE_FIRST_PASS;
    } else if (!strcmp(argv[i], "forward_pass")) {
      params->forward_pass = 1;
    } else if (!strcmp(argv[i], "noskewadj")) {
      params->noskewadj = 1;
    } else if (!strcmp(argv[i], "no_increment_hotp")) {
      params->no_increment_hotp = 1;
    } else if (!strcmp(argv[i], "nullok")) {
      params->nullok = NULLOK;
    } else if (!strcmp(argv[i], "allow_readonly")) {
      params->allow_readonly = 1;
    } else if (!strcmp(argv[i], "echo-verification-code") ||
               !strcmp(argv[i], "echo_verification_code")) {
      params->echocode = PAM_PROMPT_ECHO_ON;
    } else if (!strncmp(argv[i], "grace_period=", 13)) {
      char *remainder = NULL;
      const time_t grace = (time_t)strtol(argv[i] + 13, &remainder, 10);
      if (grace < 0 || *remainder) {
        log_message(LOG_ERR, pamh,
                    "Invalid value in setting \"%s\"."
                    "grace_period must be a positive number of seconds.",
                    argv[i]);
        return -1;
      }
      params->grace_period = grace;
    } else {
      log_message(LOG_ERR, pamh, "Unrecognized option \"%s\"", argv[i]);
      return -1;
    }
  }
  return 0;
}

static int google_authenticator(pam_handle_t *pamh,
                                int argc, const char **argv) {
  int        rc = PAM_AUTH_ERR;
  uid_t      uid = -1;
  int        old_uid = -1, old_gid = -1, fd = -1;
  char       *buf = NULL;
  struct stat orig_stat = { 0 };
  uint8_t    *secret = NULL;
  int        secretLen = 0;

  // Handle optional arguments that configure our PAM module
  Params params = { 0 };
  params.allowed_perm = 0600;
  if (parse_args(pamh, argc, argv, &params) < 0) {
    return rc;
  }

  const char *prompt = params.authtok_prompt
    ? params.authtok_prompt
    : (params.forward_pass ? PWCODE_PROMPT : CODE_PROMPT);

  // Read and process status file, then ask the user for the verification code.
  int early_updated = 0, updated = 0;

  const char* const username = get_user_name(pamh, &params);
  char* const secret_filename = get_secret_filename(pamh, &params,
                                                    username, &uid);
  int stopped_by_rate_limit = 0;

  // Drop privileges.
  {
    const char* drop_username = username;

    // If user doesn't exist, use 'nobody'.
    if (uid == -1) {
      drop_username = nobody;
      if (parse_user(pamh, drop_username, &uid)) {
        // If 'nobody' doesn't exist, bail. We need to drop privs to *someone*.
        goto out;
      }
    }

    if (drop_privileges(pamh, drop_username, uid, &old_uid, &old_gid)) {
      // Don't allow to continue without dropping privs.
      goto out;
    }
  }

  if (secret_filename) {
    fd = open_secret_file(pamh, secret_filename, &params, username, uid, &orig_stat);
    if (fd >= 0) {
      buf = read_file_contents(pamh, &params, secret_filename, &fd, orig_stat.st_size);
    }

    if (buf) {
      if (rate_limit(pamh, secret_filename, &early_updated, &buf) >= 0) {
        secret = get_shared_secret(pamh, &params, secret_filename, buf, &secretLen);
      } else {
        stopped_by_rate_limit=1;
      }
    }
  }

  const long hotp_counter = get_hotp_counter(pamh, buf);

  /*
   * Check to see if a successful login from the same host happened
   * within the grace period. If it did, then allow login without
   * an additional code.
   */
  if (buf && within_grace_period(pamh, &params, buf)) {
    rc = PAM_SUCCESS;
    log_message(LOG_INFO, pamh,
                "within grace period: \"%s\"", username);
    goto out;
  }

  // Only if nullok and we do not have a code will we NOT ask for a code.
  // In all other cases (i.e "have code" and "no nullok and no code") we DO ask for a code.
  if (!stopped_by_rate_limit &&
        ( secret || params.nullok != SECRETNOTFOUND )
     ) {

    if (!secret) {
      log_message(LOG_WARNING , pamh, "No secret configured for user %s, asking for code anyway.", username);
    }

    int must_advance_counter = 0;
    char *pw = NULL, *saved_pw = NULL;
    for (int mode = 0; mode < 4; ++mode) {
      // In the case of TRY_FIRST_PASS, we don't actually know whether we
      // get the verification code from the system password or from prompting
      // the user. We need to attempt both.
      // This only works correctly, if all failed attempts leave the global
      // state unchanged.
      if (updated || pw) {
        // Oops. There is something wrong with the internal logic of our
        // code. This error should never trigger. The unittest checks for
        // this.
        if (pw) {
          explicit_bzero(pw, strlen(pw));
          free(pw);
          pw = NULL;
        }
        rc = PAM_AUTH_ERR;
        break;
      }
      switch (mode) {
      case 0: // Extract possible verification code
      case 1: // Extract possible scratch code
        if (params.pass_mode == USE_FIRST_PASS ||
            params.pass_mode == TRY_FIRST_PASS) {
          pw = get_first_pass(pamh);
        }
        break;
      default:
        if (mode != 2 && // Prompt for pw and possible verification code
            mode != 3) { // Prompt for pw and possible scratch code
          rc = PAM_AUTH_ERR;
          continue;
        }
        if (params.pass_mode == PROMPT ||
            params.pass_mode == TRY_FIRST_PASS) {
          if (!saved_pw) {
            // If forwarding the password to the next stacked PAM module,
            // we cannot tell the difference between an eight digit scratch
            // code or a two digit password immediately followed by a six
            // digit verification code. We have to loop and try both
            // options.
            saved_pw = request_pass(pamh, params.echocode, prompt);
          }
          if (saved_pw) {
            pw = strdup(saved_pw);
          }
        }
        break;
      }
      if (!pw) {
        continue;
      }

      // We are often dealing with a combined password and verification
      // code. Separate them now.
      const int pw_len = strlen(pw);
      const int expected_len = mode & 1 ? 8 : 6;
      char ch;

      // Full OpenSSH "bad password" is "\b\n\r\177INCORRECT", capped
      // to original password length.
      if (pw_len > 0 && pw[0] == '\b') {
        log_message(LOG_INFO, pamh,
                    "Dummy password supplied by PAM."
                    " Did OpenSSH 'PermitRootLogin <anything but yes>' or some"
                    " other config block this login?");
      }

      if (pw_len < expected_len ||
          // Verification are six digits starting with '0'..'9',
          // scratch codes are eight digits starting with '1'..'9'
          (ch = pw[pw_len - expected_len]) > '9' ||
          ch < (expected_len == 8 ? '1' : '0')) {
      invalid:
        explicit_bzero(pw, pw_len);
        free(pw);
        pw = NULL;
        continue;
      }
      char *endptr;
      errno = 0;
      const long l = strtol(pw + pw_len - expected_len, &endptr, 10);
      if (errno || l < 0 || *endptr) {
        goto invalid;
      }
      const int code = (int)l;
      memset(pw + pw_len - expected_len, 0, expected_len);

      if ((mode == 2 || mode == 3) && !params.forward_pass) {
        // We are explicitly configured so that we don't try to share
        // the password with any other stacked PAM module. We must
        // therefore verify that the user entered just the verification
        // code, but no password.
        if (*pw) {
          goto invalid;
        }
      }

      // Only if we actually have a secret will we try to verify the code
      // In all other cases will we just remain at PAM_AUTH_ERR
      if (secret) {
        // Check all possible types of verification codes.
        switch (check_scratch_codes(pamh, &params, secret_filename, &updated, buf, code)) {
        case 1:
          if (hotp_counter > 0) {
            switch (check_counterbased_code(pamh, secret_filename, &updated,
                                            &buf, secret, secretLen, code,
                                            hotp_counter,
                                            &must_advance_counter)) {
            case 0:
              rc = PAM_SUCCESS;
              break;
            case 1:
              goto invalid;
            default:
              break;
            }
          } else {
            switch (check_timebased_code(pamh, secret_filename, &updated, &buf,
                                         secret, secretLen, code, &params)) {
            case 0:
              rc = PAM_SUCCESS;
              break;
            case 1:
              goto invalid;
            default:
              break;
            }
          }
          break;
        case 0:
          rc = PAM_SUCCESS;
          break;
        default:
          break;
        }

        break;
      }
    }

    // Update the system password, if we were asked to forward
    // the system password. We already removed the verification
    // code from the end of the password.
    if (rc == PAM_SUCCESS && params.forward_pass) {
      if (!pw || pam_set_item(pamh, PAM_AUTHTOK, pw) != PAM_SUCCESS) {
        rc = PAM_AUTH_ERR;
      }
    }

    // Clear out password and deallocate memory
    if (pw) {
      explicit_bzero(pw,strlen(pw));
      free(pw);
    }
    if (saved_pw) {
      explicit_bzero(saved_pw, strlen(saved_pw));
      free(saved_pw);
    }

    // If an hotp login attempt has been made, the counter must always be
    // advanced by at least one, unless this has been disabled.
    if (!params.no_increment_hotp && must_advance_counter) {
      char counter_str[40];
      snprintf(counter_str, sizeof counter_str, "%ld", hotp_counter + 1);
      if (set_cfg_value(pamh, "HOTP_COUNTER", counter_str, &buf) < 0) {
        rc = PAM_AUTH_ERR;
      }
      updated = 1;
    }

    // Display a success or error message
    if (rc == PAM_SUCCESS) {
      log_message(LOG_INFO , pamh, "Accepted google_authenticator for %s", username);
      if (params.grace_period != 0) {
        if (update_logindetails(pamh, &params, &buf)) {
          log_message(LOG_ERR, pamh, "Failed to store grace_period timestamp in config");
        }
      }
    } else {
      log_message(LOG_ERR, pamh, "Invalid verification code for %s", username);
    }
  }

  // If the user has not created a state file with a shared secret, and if
  // the administrator set the "nullok" option, this PAM module completes
  // without saying success or failure, without ever prompting the user.
  // It's not a failure since "nullok" was specified, and it's not a success
  // because it must be distinguishable from "good credentials given" in
  // case the PAM config considers this module "sufficient".
  // (or more complex equivalents)
  if (params.nullok == SECRETNOTFOUND) {
    rc = PAM_IGNORE;
  }

  // Persist the new state.
  if (early_updated || updated) {
    int err;
    if ((err = write_file_contents(pamh, &params, secret_filename, &orig_stat, buf))) {
      // Inform user of error if the error is clearly a system error
      // and not an auth error.
      char s[1024];
      switch (err) {
      case EPERM:
      case ENOSPC:
      case EROFS:
      case EIO:
      case EDQUOT:
        snprintf(s, sizeof(s), "Error \"%s\" while writing config", strerror(err));
        conv_error(pamh, s);
      }

      // If allow_readonly parameter is defined than ignore write errors and
      // allow user to login.
      if (!params.allow_readonly) {
        // Could not persist new state. Deny access.
        rc = PAM_AUTH_ERR;
      }
    }
  }

out:
  if (params.debug) {
    log_message(LOG_INFO, pamh,
                "debug: end of google_authenticator for \"%s\". Result: %s",
                username, pam_strerror(pamh, rc));
  }
  if (fd >= 0) {
    close(fd);
  }
  if (old_gid >= 0) {
    if (setgroup(old_gid) >= 0 && setgroup(old_gid) == old_gid) {
      old_gid = -1;
    }
  }
  if (old_uid >= 0) {
    if (setuser(old_uid) < 0 || setuser(old_uid) != old_uid) {
      log_message(LOG_EMERG, pamh, "We switched users from %d to %d, "
                  "but can't switch back", old_uid, uid);
    }
  }
  free(secret_filename);

  // Clean up
  if (buf) {
    explicit_bzero(buf, strlen(buf));
    free(buf);
  }
  if (secret) {
    explicit_bzero(secret, secretLen);
    free(secret);
  }
  return rc;
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
