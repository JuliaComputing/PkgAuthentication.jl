# PkgAuthentication

Authentication to private Julia package servers

```
    authenticate(pkgserver)

Starts browser based pkg-server authentication (blocking).

`pkgserver` must be a URL pointing to a server that provides the `/pkgserver/challenge`,
`/pkgserver/response`, and `/pkgserver/claimtoken` endpoints.
```

## Installation
1. Make sure the PkgAuthentication.jl is part of the default Julia environment.
2. Put the following into your `startup.jl` to enable authentication for server as configured in JULIA_PKG_SERVER environment variable.
```julia
# create a new anonymous module for the init code
Base.eval(Module(), quote
    using PkgAuthentication, Pkg

    SERVER = string(Pkg.pkg_server())

    function authenticate(url, svr, err)
        ret = PkgAuthentication.authenticate(string(svr, "/auth"), tries = 3)
        if ret isa PkgAuthentication.Success
            @info "Authentication successful."
        else
            @error "Failed to authenticate to $(svr)." exception=ret
        end
        return true, false
    end

    function register_auth_handler(pkgserver::Union{Regex, AbstractString})
        return Pkg.PlatformEngines.register_auth_error_handler(pkgserver, authenticate)
    end

    if PkgAuthentication.is_new_auth_mechanism()
        register_auth_handler(SERVER)
    else
        # old Julia versions don't support auth hooks, so let's authenticate now and be done with it
        authenticate(SERVER)
    end
end)
```

## Implementation

Authentication is implemented with the following state machine:

![structure](structure.png)
