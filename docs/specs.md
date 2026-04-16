# ztts - zero trust token service

The ztts is a golang implementation of a JWT service. The purpose is to enable configurable, policy-controlled generation of new tokens.

The protocol should support authenticated requests using JWTs and produces JWTs (or error messages) as the result of an exchange. Requests are processed according to the following:

1. A request to the service is a JSON object with the following items: 
    - profile: the requested token profile
    - scopes: a set of requested scopes for the new token
    - userid: a user on behalf of whom the operations will be done
    - tenant: the id of a tenant where the user exists
2. Authentication is validated - either by JWT signature validation or by mTLS validation.
3. A set of authenticated claims are assembled. From JWT validation this is the claims in the token itself. The request items are added to the authenticated claims.
4. The service maintains a set of token profiles. Each token profile has an associated set of spocp rules for authorization. 
5. The service builds a query from the authenticated claims and matches these against the ruleset for the requested profile. If permission is given the token is created and returned.

Token creation for a profile should be configurable. The requesting client (identified using aud in the JWT token) is always the outgoing aud and the server is the iss for the new token.

The service should support creating bootstrap tokens for a given aud using an admin interface and it should be possible for a service to regularly use this bootstrap token to authenticate and request another bootstrap token (such a ruleset and profile should be provided as an example) as a way to maintain an authentication capability with the token service. Token profiles should specify a validity period and it should be possible, but not automatically permitted for a token of a certain profile to be used to request another of the same profile (renewal). Token processing that isn't explicitly permitted by a rule is denied.

The service should support blocking and revoking issued tokens.

The service should protect itself against replay attacks.