# Internal implementation notes

The authentication control flow is implemented as the following state machine, starting from the `NeedAuthentication` state (or `NoAuthentication` if `force=true` is passed to `authenticate`), and finishing in either `Success` or `Failure`.

```mermaid
---
title: PkgAuthentication state machine diagram
---

stateDiagram-v2
    direction LR

    [*] --> NeedAuthentication
    [*] --> NoAuthentication

    NeedAuthentication --> HasToken
    NeedAuthentication --> NoAuthentication
    note right of NeedAuthentication
        Checks if a syntactically valid auth.toml token file
        exists for the requested server (but does not check
        whether it has expired or not). Proceeds to HasToken
        if it exists, or NoAuthentication if not.
    end note

    HasToken --> NeedRefresh
    HasToken --> Success
    note right of HasToken
        If the token is valid (i.e. not expired, based on the
        expiry times in the auth.toml file), proceeds to Success.
        Otherwise, proceeds to NeedRefresh.
    end note

    NeedRefresh --> NoAuthentication
    NeedRefresh --> HasNewToken
    NeedRefresh --> Failure
    note right of NeedRefresh
        Attempts to acquire a new access token by using the refresh
        token in the auth.toml. If the refresh succeeds, it will
        proceed to HasNewToken, or to NoAuthentication if it fails.
    end note

    NoAuthentication --> RequestLogin
    NoAuthentication --> Failure
    note left of NoAuthentication
        Attempts to acquire an OAuth challenge from the Pkg server.
        If successful, proceeds to RequestLogin, or to Failure
        otherwise.
    end note

    HasNewToken --> HasNewToken
    HasNewToken --> Success
    HasNewToken --> Failure
    note left of HasNewToken
        Takes the token from the previous step and writes it to the
        auth.toml file. In order to handle potential race conditions
        with other writes, it will check that the write was succeful,
        and will try again if it fails. If the write was successful,
        it proceeds to Success, or retries HasNewToken if it was not.
        May proceed to Failure if there is an unexpected failure.
    end note

    RequestLogin --> ClaimToken
    RequestLogin --> Failure
    note right of RequestLogin
        Presents the in-browser step of the OAuth authentication process
        to the user (e.g. by opening the Pkg server's login page in the
        user's browser). Proceeds to ClaimToken immediately, or to Failure
        if there was an unexpected failure.
    end note

    ClaimToken --> ClaimToken
    ClaimToken --> HasNewToken
    ClaimToken --> Failure
    note left of ClaimToken
        Starts polling the Pkg server's OAuth token claiming endpoint,
        returning to ClaimToken while the polling is happening. Proceeds
        to HasNewToken if it successfully acquires a token, or to Failure
        if the polling times out, or there is an unexpected error.
    end note

    Success --> [*]
    Failure --> [*]
```
