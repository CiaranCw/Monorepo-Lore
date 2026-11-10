# AuthBridge

AuthBridge implements the Lore identity and token-exchange calls the 0.10.1 client and server actually make.

Login checks the username and password, then the Lore CLI stores the identity token. Exchange builds an access token from the caller's current module grants. Read and write both become Lore access, because this Lore version has no separate read-only mode.

Access tokens expire after five minutes. Disable, revoke, and stopping the Manager do not invalidate a token that was already issued. The next exchange omits revoked repositories.

CreateResource checks that the caller has a live identity. It does not grant a module.
