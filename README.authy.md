# Google Authenticator PAM module with Authy push notification

PAM authentication using Authy (https://authy.com/) push notifications.

This repository is a fork of the "Google Authenticator PAM module"
https://github.com/google/google-authenticator-libpam with an extra
extension to send Authy push notification.

## Build, install, setup
See https://github.com/google/google-authenticator-libpam

Authy extension requires the following extra dependencies:
- libjansson
- libcurl

If running Debian-based distro, do:
```
sudo apt install libjansson-dev libcurl4-gnutls-dev
```

## Extra PAM module options
### enable_authy
If set, Authy extension is enabled. PAM module sends push notification
to the Authy authenticator on user login. If authentication passes,
login is granted. On failure, the classic Google OTP is used.

## Extra .google_authenticator fields
To setup Authy authentication, generate .google_authenticator file as described
in https://github.com/google/google-authenticator-libpam and add the following
extra fields.

### AUTHY_ID
See https://support.authy.com/hc/en-us/articles/360016449054-Find-your-Authy-ID
how to find out your Authy ID.

Example:
```
" AUTHY_ID 123456789"
```
### AUTHY_API_KEY
See: https://www.twilio.com/docs/authy/twilioauth-sdk/quickstart/obtain-authy-api-key

Obtaining an Authy API Key:
1. Create a Twilio account: https://www.twilio.com/try-twilio
2. Create an Authy application in the Twilio Console.
3. Once you've created a new Authy application, copy the API Key for
Production available in the Settings page of your Authy application.

Example:
```
" AUTHY_API_KEY aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpP
```

### .google_authenticator example
```
00000000000000000000000000
" RESETTING_TIME_SKEW 52968321+21 52968328+21 52968508+20
" RATE_LIMIT 3 30 1589055237
" WINDOW_SIZE 17
" TOTP_AUTH
" AUTHY_ID 000000000
" AUTHY_API_KEY xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
11111111
22222222
33333333
"
```

### TODO: add Authy fields generation in google-authenticator tool
