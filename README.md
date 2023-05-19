# PkgAuthentication

Interactive browser-based authentication to private Julia Pkg servers.

## Setup

#### Step 1: Make sure that PkgAuthentication.jl is installed in the default global Julia package environment (`v1.x`)

```julia
julia> delete!(ENV, "JULIA_PKG_SERVER");

julia> import Pkg

julia> Pkg.activate("v$(VERSION.major).$(VERSION.minor)"; shared = true)

julia> Pkg.add("PkgAuthentication")
```

#### Step 2: Set the `JULIA_PKG_SERVER` environment variable

One easy way to set the `JULIA_PKG_SERVER` environment variable is to add the following
line to your [`startup.jl`](https://docs.julialang.org/en/v1/manual/getting-started/) file:

```julia
ENV["JULIA_PKG_SERVER"] = "my-pkg-server.example.com"
```

#### Step 3: Put the following snippet into your [`startup.jl`](https://docs.julialang.org/en/v1/manual/getting-started/) file

```julia
# create a new anonymous module for the init code to not pollute the global namespace
Base.eval(Module(), quote
    import PkgAuthentication
    PkgAuthentication.install();
end)
```

With the above snippet, Pkg will automatically prompt you when you need to authenticate.

However, if you want to authenticate immediately (instead of waiting until the first
Pkg operation that needs authentication), you can do so as follows. First, make
sure that you have completed steps 1, 2, and 3 above. Then, open the Julia REPL
and run the following:

```julia
julia> import PkgAuthentication

julia> PkgAuthentication.authenticate();
```

## Adding new registries

If you are using this private Pkg server for the first time, you probably want to
make sure that you add any private registries that might be served by this Pkg server.

First, make sure that you have completed steps 1, 2, and 3 above. Then, open the
Julia REPL and run the following:

```julia
julia> import Pkg

julia> Pkg.Registry.add()

julia> Pkg.Registry.update()
```

## Implementation

Authentication is implemented with the following state machine:

```mermaid
---
title: PkgAuthentication state machine diagram
---

stateDiagram-v2
    direction LR

    [*] --> NeedAuthentication

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
    note right of NoAuthentication
        Attempts to acquire an OAuth challenge from the Pkg server.
        If successful, proceeds to RequestLogin, or to Failure
        otherwise.
    end note

    HasNewToken --> HasNewToken
    HasNewToken --> Success
    HasNewToken --> Failure
    note right of HasNewToken
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
    note right of ClaimToken
        Starts polling the Pkg server's OAuth token claiming endpoint,
        returning to ClaimToken while the polling is happening. Proceeds
        to HasNewToken if it successfully acquires a token, or to Failure
        if the polling times out, or there is an unexpected error.
    end note
```
