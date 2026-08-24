# TODOs

## `varlinkctl-http`

* `server-ca-file` and `client-cert-file`/`client-key-file` are on-per-client
  rather than one-per-host, so a client talking to several servers can only
  ever present one identity and trust one CA.

* `known-hosts` TOFU is currently enabled by default, should it be opt-in?

* `known-hosts` is currently completely ignored when CA-issued cert is observed.
  Should we check `known-hosts` and warn on/remove entries we observe a valid cert
  for to guard against later downgrade to self-signed cert?
