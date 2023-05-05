---
name: TOTP codes are not accepted
about: OTP codes are configured, but don't seem to be accepted, or only sometimes
  accepted
title: 'TOTP not accepted: '
labels: ''
assignees: ''

---

## Prerequisite

Read [this](https://twitter.com/thomashabets/status/1133780752582217728), have a little chuckle to yourself.

After that: no seriously really do confirm it. Most of the reported issues with TOTP follow that pattern.

## PAM config

E.g. `/etc/pam.d/ssh`, or `common-auth` if it uses that.

## SSH config (or equivalent if not using SSH)

`/etc/ssh/sshd_config`

## Enable `debug` on the module, and paste what's logged

Maybe from `/var/log/auth.log`.
