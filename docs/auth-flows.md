# Authentication Flows

If authentication is required, Julia uses [bearer tokens (RFC 6750)](https://datatracker.ietf.org/doc/html/rfc6750) to authenticate package server requests.
That is, the HTTP requests set the `Authorization: Bearer $(access_token)` header when fetching data from the package server.

PkgAuthentication.jl manages acquiring these tokens from package server, generally via an interactive flow.
This document describes the protocols related to the authentication,
and also acts as a specification for a few PkgAuthentication-specific conventions that _authenticated_ package servers should follow.

Additional resources & references:

- [Original implementation notes `JuliaLang/Pkg.jl#1538`](https://github.com/JuliaLang/Pkg.jl/pull/1538#issuecomment-564118431)

_Note: the discussions of the package server protocol itself (i.e. downloading of registires, packages, and artifacts) is out of scope of this document._

## Authenticated package requests & `auth.toml` files

Julia (i.e. Pkg.jl - the package manager) stores the token information in a `auth.toml` file in the "server directory" at `~/.julia/servers/{hostname}/auth.toml`.

Pkg uses the following top-level key values pairs:

- `access_token` (REQUIRED): the bearer token used to authorize normal requests (string)
- `expires_at` (OPTIONAL): an absolute expiration time (seconds from UNIX epoch; integer)
- `expires_in` (OPTIONAL): a relative expiration time (seconds; integer)
- `refresh_url` (OPTIONAL): URL to fetch a new token from (string)
- `refresh_token` (OPTIONAL): bearer token used to authorize refresh requests (string)

The `auth.toml` file may contain other fields (e.g. a username, or user email), but they are ignored by Pkg.

The two other fields mentioned in RFC6750 are `token_type` and `scope`.
These are omitted since only Bearer tokens are currently supported, and the scope is always implicitly to provide access to Pkg protocol URLs.
Pkg servers, however, SHOULD NOT send `auth.toml` files with `token_type` or `scope` fields, as these names may be used in the future, e.g. to support other kinds of tokens or to limit the scope of an authorization to a subset of Pkg protocol URLs.

As an example, a valid `auth.toml` file might look something like this:

```toml
access_token = "ey...vSA"
expires_at = 1742014471
expires_in = 86400
refresh_url = "https://juliahub.com/auth/renew/token.toml/v2/"
refresh_token = "Ch...du"
```

Note: the server directory path can be determined with `Pkg.PlatformEngines.get_server_dir`.

### Token Expiration & Refresh

Pkg will determine whether the access token needs to be refreshed by examining the `expires_at` and/or `expires_in` fields of the auth file.
The expiration time is the minimum of `expires_at` and `mtime(auth_file) + expires_in`.
When the Pkg client downloads a new `auth.toml` file, if there is a relative `expires_in` field, an absolute `expires_at` value is computed based on the client's current clock time.
This combination of policies allows expiration to work gracefully even in the presence of clock skew between the server and the client.

If the access token is expired and there are `refresh_token` and `refresh_url` fields in `auth.toml`, a new auth file is requested by making a request to `refresh_url` with an `Authorization: Bearer $(refresh_token)` header.
Pkg will refuse to make the refresh request unless `refresh_url` is an HTTPS URL.

Note that `refresh_url` need not be a URL on the Pkg server: token refresh can be handled by separate server.
If the request is successful and the returned `auth.toml` file is a well-formed TOML file with _at least_ an `access_token` field, it is saved to server directory, replacing the existing `auth.toml` file.

Checking for access token expiry and refreshing `auth.toml` is done before each Pkg client request to a Pkg server.
If the auth file is updated, the new access token is used, so the token should, in theory, always be up to date.

Practice is different from theory, of course, and if the Pkg server considers the access token expired, it may return an HTTP `401 Unauthorized` status code in the response.
Then, the Pkg client should attempt to refresh the auth token.
If, after attempting to refresh the access token, the server still returns HTTP `401 Unauthorized`, the Pkg client server will present the body of the error response to the user or user agent (IDE).

## Acquiring Authentication Tokens

PkgAuthentication is designed to assist the user in acquiring authentication tokens by performing an interactive, browser-based authentication flow.

The following information is necessary to start the authentication flow, to know which URL to request the token from:

* `pkg_server`: the package server URL; i.e. the value that is used (and generally automatically determined from) the `JULIA_PKG_SERVER` environment variable.
* `auth_suffix`: specifies an additional URL suffix to append to the `pkg_server` URL to form the authentication URLs. This defaults to `/auth`.

### Notational Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this specification are to be interpreted as described in [RFC2119](https://datatracker.ietf.org/doc/html/rfc2119).

### Authentication mechanisms

PkgAuthentication.jl supports two different authentication mechanisms:
1. Classic Authentication Flow
2. Device Authentication Flow

When initiating a fresh authentication, PkgAuthentication.jl calls `/auth/configuration` endpoint to determine whether the Pkg server supports device authentication. This endpoint MUST return a 200 response. When device authentication is not supported by the server the response body MUST contain the following JSON data :

```json
{
  "device_flow_supported": false,
  "refresh_url": "https://juliahub.com/auth/renew/token.toml/v2/"
}
```

In this case, PkgAuthentication.jl will execute the Classic Authentication Flow. When device authentication _is_ supported by the server, the response body MUST contain:

```json
{
  "device_flow_supported": true,
  "refresh_url": "https://juliahub.com/auth/renew/token.toml/device/",
  "device_authorization_endpoint": "https://auth.juliahub.com/auth/device/code",
  "token_endpoint": "https://auth.juliahub.com/auth/token"
}
```

In this case, PkgAuthentication.jl will execute the Device Authentication Flow.

Note: URLs in the examples are only representative. Actual URLs may differ.

### Classic Authentication Flow

The classic authentication flow is similar to the [OAuth 2.0 Authorization Code Grant flow](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1), but uses different conventions for endpoints.

The flow goes through the following steps:

1. Generating an 32 byte random challenge string.

2. Requesting a challenge from the Pkg server.

   ```
   POST $(pkg_server)/$(auth_suffix)/challenge
   ```

   The body of the request should be the challenge string (just plain bytes, not encoded as JSON or anything).

   The server MUST respond with the status code `200` and a body containing the response URL fragment `response` (again, plain bytes, no encoding of any form).

3. Opening the response URL fragment in the user's browser.

   At this point, the user should open the following URL in a web browser (that is logged into the package server) and approve the authentication request:

   ```
   $(pkg_server)/$(auth_suffix)/response?$(response)
   ```

   The package server SHOULD implement a basic interface for the user to approve or deny the authentication request.
   It SHOULD also indicate which user is logged in and which package server is being authenticated against.
   When the user approves the request, it SHOULD indicate to the user that the request has been approved and that they can close the browser window and return to their application.

4. Polling the package server's token claiming endpoint.

   While waiting for the user to approve the authentication request in step (3), PkgAuthentication will poll the package server's token claiming endpoint.
   The polling is done by sending a POST request

   ```
   POST $(pkg_server)/$(auth_suffix)/claimtoken
   ```

   with the following request body

   ```json
   {
     "challenge": "$(challenge)",
     "response": "$(response)"
   }
   ```

   If the authentication request is valid, the server MUST respond with the status code `200`.
   If the authentication request is invalid or expired, a non-`200` status code MUST be returned.

   If the authentication request is valid, the server MUST respond with a JSON object.

   If the user has completed the interactive authentication flow in the browser, the request body MUST contain a `token` property.
   The `token` property MUST itself be a JSON object, and it minimally MUST contain an `access_token` value (which in turn contains the token value that can be used as the bearer token when performing package server requests).

   All the fields of the `token` property will be stored in the `auth.toml` file.
   As such, the response MAY return additional fields, to either set the standard options `auth.toml` fields, or any additional fields the package server deems useful.

   If the user has not yet completed the interactive authentication flow in the browser, the request body MAY contain an `expiry` property, which MUST be an integer and indicates time at which the response/challenge pair will expire on the server.

5. Constructing the `auth.toml` file.

   If PkgAuthentication successfully acquires a token from polling the `/claimtoken` endpoint, it will write the token to the `auth.toml` file.
   It will write out all the keys and values of the `token` in the `auth.toml` file as TOML.

### Device Authentication Flow

Device flow authentication enables an application to authenticate a user by providing a link that can be opened on another device where the user can proceed with authentication. The application will be able to check whether the user has completed authentication on the other device by calling certain APIs. Finally, the application can retrieve the users OAuth token via the same API call. Device flow authentication becomes necessary on devices that do not have a browser based interface for regular login or applications that are not browser based such as command line applications. More details [here](https://datatracker.ietf.org/doc/html/rfc8628).

The flow goes through the following steps:

1. A `POST` request MUST be made to the `device_authorization_endpoint` with the headers `Accept: application/json` and `Content-Type: application/x-www-form-urlencoded`. The body of the request MUST contain the url encoded `client_id` and `scope` values.

    The server MUST respond with a 200 status and a body containing a JSON encoded structure. The JSON structure MUST include a `device_code` and a `verification_uri_complete` among other values. Example:

    ```json
    {
       "device_code": "abcdefghijklmnopqrstuvwxyz1234567890",
       "user_code": "FJMC-LPVR",
       "verification_uri": "https://juliahub.com/dex/device",
       "verification_uri_complete": "https://juliahub.com/dex/device?user_code=FJMC-LPVR",
       "expires_in": 300,
       "interval": 5
    }
    ```

2. The client should open `verfication_uri_complete` in the browser so that the user can login and approve the authorization request. The package server SHOULD provide an interface for the user to login and approve or deny the authorization request.

3. The client should now poll for completion of the authorization request. It can do so by making a `POST` request to the `token_endpoint` with the same headers as was used for the `device_authorization_endpoint` call. The body of the request MUST contain the url encoded `client_id` and `scope`. The values of these parameters must match the values sent for `device_authorization_endpoint`. In addition to these two parameters, a `grant_type` and `device_code` parameter must also be included with values `urn:ietf:params:oauth:grant-type:device_code` and the `device_code` response value from the `device_authorization_endpoint` call, respectively.

    While the user hasn't finished responding to the authorization request or has denied the authorization request, the `token_endpoint` response status must be `401` or `400`.

    When the user approves the authorization request, the `token_endpoint` response status must be 200 with a JSON body containing the `access_token`, `id_token`, `refresh_token` and `expires_in`. Example:

    ```json
    {
      "access_token": "abcdefghijklmnopqrstuvwxyz1234567890",
      "token_type": "bearer",
      "expires_in": 86399,
      "refresh_token": "abcdefghijklmnopqrstuvwxyz1234567890",
      "id_token": "abcdefghijklmnopqrstuvwxyz1234567890"
    }
    ```

4. The client must generate the `auth.toml` file with the above values. The following extra key/values must be added by the client to the auth.toml:
    - `expires_at: <expires_in> + <time()>` This value is required to determine whether the token is expired and needs refresh. This is missing in the token response so it must be added by summing the `expires_in` value with the current timestamp.
    - `refresh_url` This value is also missing in the device token response but is necessary for refreshing expired tokens. This field must be added with value same as the `refresh_url` from the `device_authorization_endpoint` response.

#### Client ID for device authentication flow

The `client_id` parameter for device authentication can be configured by setting the environment variable `JULIA_PKG_AUTHENTICATION_DEVICE_CLIENT_ID`. This value defaults to `"device"`.
