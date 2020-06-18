# PkgAuthentication

Authentication to private Julia package servers

```
    authenticate(pkgserver)

Starts browser based pkg-server authentication (blocking).

`pkgserver` must be a URL pointing to a server that provides the `pkgserver/challenge`,
`pkgserver/response`, and `pkgserver/claimtoken` endpoints.
```

## Example Usage

Use `PkgAuthentication.is_new_auth_mechanism()` to check if the currently installed
version of Pkg supports authentication hooks. If so, register a hook with e.g.
``````
function register_auth_handler(pkgserver::Union{Regex, AbstractString})
    tries = 0
    return Pkg.PlatformEngines.register_auth_error_handler(pkgserver, (url, svr, err) -> begin
        server = string(svr, "/auth")
        cmd = ```
            $(first(Base.julia_cmd()))
            --project="/home/pfitzseb/.julia/dev/JTPkgAuth/" # FIXME
            -e "using PkgAuthentication; PkgAuthentication.authenticate(\"$(server)\")"
            ```
        try
            run(cmd, wait = true)
        catch err
            @error "PkgServer authentication handler failed."
            return false, false
        end

        tries += 1
        return true, tries < 3
    end)
end
``````

If not, start the external process at some other time, e.g. on startup.
