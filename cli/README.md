# KeyNest CLI

The CLI never accepts a secret value in a command argument and `run` never writes `.env`. It reads a scoped service token from a user-only configuration file after `login`; do not use this MVP storage mode on shared hosts. Prefer `KEYNEST_TOKEN` injection from an OS/CI secret store and add the device-authorization/OS-keychain adapter before a public release.

```bash
keynest login --server https://keynest.example.com --token knst_...
keynest run --environment ENVIRONMENT_UUID -- node server.js
```

The child receives its existing environment plus the authorized secret values. Its exit code is preserved, and Ctrl+C/Unix termination signals are relayed to it. On operating systems, appropriately privileged users may inspect another process’s environment; see the root security policy.
