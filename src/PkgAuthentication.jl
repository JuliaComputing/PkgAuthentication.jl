module PkgAuthentication

using HTTP, Random, JSON, Pkg, Dates

const TIMEOUT = 180 # seconds
const MAX_FAILURES = 5 # maximum number of failed requests
const HEADERS = []

function open_browser(url)
    try
        if Sys.iswindows()
            return run(`cmd /c "start $url"`)
        elseif Sys.islinux()
            return run(`xdg-open $url`)
        elseif Sys.isbsd()
            return run(`xdg-open $url`)
        elseif Sys.isapple()
            return run(`open $url`)
        end
    catch err
        @debug err
    finally
        printstyled("\nAuthentication required.\n"; bold = true, color = :yellow)
        println("""
        Opening $(url) to authenticate.
        """)
    end
end

is_new_auth_mechanism() = isdefined(Pkg, :PlatformEngines) &&
                          isdefined(Pkg.PlatformEngines, :get_server_dir) &&
                          isdefined(Pkg.PlatformEngines, :register_auth_error_handler)

function token_path(url)
    if is_new_auth_mechanism()
        joinpath(Pkg.PlatformEngines.get_server_dir(url), "auth.toml")
    else
        get(ENV, "JULIA_PKG_TOKEN_PATH", joinpath(homedir(), ".julia", "token.toml"))
    end
end

"""
    fetch_response(url, challenge)

Fetches the server's response to `challenge` (a string) or `nothing` if the request failed.
"""
function fetch_response(url, challenge)
    r = HTTP.post(url, HEADERS, string(challenge), status_exception = false)
    r.status == 200 ? String(r.body) : nothing
end

"""
    claim_token(url, challenge, response; failed = 0)

Tries to get the token from `url` based on `challenge` and `response`.

Returns a tuple `(success, failed, expires_in)`, where `success` indicates that the token has been
fetched and written to disk. `failed` is incremented by one and returned if the token request failed
with a non-200 status code.
"""
function claim_token(url, challenge, response; failed = 1)
    r = HTTP.post(
        url,
        HEADERS,
        """
        {
            "challenge": "$(challenge)",
            "response": "$(response)"
        }
        """,
        status_exception = false
    )

    if r.status == 200 # request understood
        b = JSON.parse(String(r.body))

        if haskey(b, "token") # token returned. success.
            token = b["token"]


            open(token_path(url), "w") do io
                Pkg.TOML.print(io, token)
            end
            printstyled("\nAuthentication succesful.\n\n", bold = true, color=:green)
            return true, 0, 0.0
        elseif haskey(b, "expiry") # server received challenge, but user is not authorized yet.
            expiry = floor(TimePeriod(Dates.unix2datetime(b["expiry"]) - now(UTC)), Second).value
            return false, failed, expiry
        else # server never received challenge, aborting.
            return false, typemax(Int), 0.0
        end
    end
    # network error. possibly retry a couple of times:
    return false, failed+1, Inf
end

function print_no_conn(pkgserver)
    printstyled("\nCannot reach authentication server at $(pkgserver) or authentication failed.\n", bold = true, color = :red)
    println("Please check your internet connection and firewall settings.\n")
end

function print_manual(pkgserver)
    authurl = pkgserver
    println("""
    Alternatively, open

    $(authurl)

    in a browser, authenticate, and save the downloaded file at

    $(token_path(pkgserver))

    Press Enter when you're done...
    """)
    readline()
end

"""
    authenticate(pkgserver)

Starts browser based pkg-server authentication (blocking).

`pkgserver` must be a URL pointing to a server that provides the `pkgserver/challenge`,
`pkgserver/response`, and `pkgserver/claimtoken` endpoints.
"""
function authenticate(pkgserver)
    try
        challenge = Random.randstring(32)

        response = fetch_response(string(pkgserver, "/challenge"), challenge)

        if response == nothing
            print_no_conn(pkgserver)
            print_manual(pkgserver)
            return
        end

        open_browser(string(pkgserver, "/response?", response))

        start_time = time()
        expires_in = Inf
        sleep_time = 2 # could adjust this dynamically based on start_time and expires_in, but doesn't seem worth it
        failed = 0

        while true
            (time() - start_time)/1e6 > TIMEOUT && break

            sleep(sleep_time)

            success, failed, expires_in = claim_token(
                string(pkgserver, "/claimtoken"),
                challenge,
                response;
                failed = failed
            )

            success && return
            failed > MAX_FAILURES && break
            expires_in < sleep_time && break
        end

        if failed > MAX_FAILURES
            print_no_conn(pkgserver)
        else
            printstyled("Authentication timed out. ", bold = true, color = :yellow)
            println("Please try again.\n")
        end
        print_manual(pkgserver)
    catch err
        print_no_conn(pkgserver)
        print_manual(pkgserver)
    end
end

end # module
