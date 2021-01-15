
module PkgAuthentication

using Downloads, Random, JSON, Pkg

## abstract state types

abstract type State end

step(state::State) =
    throw(ArgumentError("no step function defined for this state: `$(state)`"))

struct Success <: State
    token::Dict{String, Any}
end

abstract type Failure <: State end

## authentication state machine

"""
    authenticate(pkgserver::AbstractString)

Starts browser based pkg-server authentication (blocking).

`pkgserver` must be a URL pointing to a server that provides the `/pkgserver/challenge`,
`/pkgserver/response`, and `/pkgserver/claimtoken` endpoints.
"""
function authenticate(
    server::AbstractString;
    force::Bool = false,
    tries::Integer = 1,
)::Union{Success, Failure}
    server = strip(server, '/')

    local state
    for i in 1:tries
        initial = force ? NoAuthentication : NeedAuthentication

        state = initial(server)
        try
            while !(isa(state, Success) || isa(state, Failure))
                state = step(state)
            end
        catch err
            state = GenericError((err, catch_backtrace()))
        end
        if state isa Success
            continue
        end
    end

    return state
end

## initial states

struct NeedAuthentication <: State
    server::String
end
function step(state::NeedAuthentication)::Union{HasToken, NoAuthentication}
    path = token_path(state.server)
    if isfile(path)
        toml = Pkg.TOML.parsefile(path)
        if is_token_valid(toml)
            return HasToken(state.server, mtime(path), toml)
        else
            return NoAuthentication(state.server)
        end
    else
        return NoAuthentication(state.server)
    end
end

struct NoAuthentication <: State
    server::String
end
function step(state::NoAuthentication)::Union{RequestLogin, Failure}
    challenge = Random.randstring(32)
    output = IOBuffer()
    response = request(
        string(state.server, "/challenge"),
        method = "POST",
        input = IOBuffer(challenge),
        output = output,
        throw = false,
    )
    if response isa Response && response.status == 200
        return RequestLogin(state.server, challenge, String(take!(output)))
    else
        return HttpError(response)
    end
end

## intermediate states

struct HasToken <: State
    server::String
    mtime::Float64
    token::Dict{String, Any}
end
function step(state::HasToken)::Union{NeedRefresh, Success}
    expiry = get(state.token, "expires_at", get(state.token, "expires", 0))
    expires_in = get(state.token, "expires_in", Inf)
    if min(expiry, expires_in + state.mtime) < time()
        return NeedRefresh(state.server, state.token)
    else
        return Success(state.token)
    end
end

struct NeedRefresh <: State
    server::String
    token::Dict{String, Any}
end
function step(state::NeedRefresh)::Union{HasNewToken, NoAuthentication, Failure}
    refresh_token = state.token["refresh_token"]
    headers = ["Authorization" => "Bearer $refresh_token"]
    output = IOBuffer()
    response = request(
        state.token["refresh_url"],
        method = "GET",
        headers = headers,
        output = output,
        throw = false,
    )
    # errors are recoverable by just getting a new token:
    if response isa Response && response.status == 200
        try
            body = JSON.parse(String(take!(output)))
            if haskey(body, "token")
                return HasNewToken(state.server, body["token"])
            end
        catch err
            @debug "invalid body received while refreshing token" exception=(err, catch_backtrace())
        end
        return NoAuthentication(state.server)
    else
        @debug "request for refreshing token failed" exception=(err, catch_backtrace())
        return NoAuthentication(state.server)
    end

    return GenericError(response)
end

struct HasNewToken <: State
    server::String
    token::Dict{String, Any}
    tries::Int
end
HasNewToken(server, token) = HasNewToken(server, token, 0)
function step(state::HasNewToken)::Union{HasNewToken, Success, Failure}
    if state.tries >= 3
        return GenericError("Failed to write token.")
    end
    path = token_path(state.server)
    mkpath(dirname(path))
    try
        open(path, "w") do io
            Pkg.TOML.print(io, state.token)
        end
        if Pkg.TOML.parsefile(path) == state.token
            return Success(state.token)
        else
            return HasNewToken(state.server, state.token, 0)
        end
    catch err
        @debug "failed to write token" exception=(err, catch_backtrace())
        return GenericError("Failed to write token.")
    end
end

struct RequestLogin <: State
    server::String
    challenge::String
    response::String
end
function step(state::RequestLogin)::Union{ClaimToken, Failure}
    success = open_browser(string(state.server, "/response?", state.response))
    if success
        return ClaimToken(state.server, state.challenge, state.response)
    else # this can only happen for the browser hook
        return GenericError("Failed to execute open_browser hook.")
    end
end

struct ClaimToken <: State
    server::String
    challenge::String
    response::String
    expiry::Float64
    start_time::Float64
    timeout::Float64
    poll_interval::Float64
    failures::Int
    max_failures::Int
end
ClaimToken(server, challenge, response, expiry = Inf, failures = 0) =
    ClaimToken(server, challenge, response, expiry, time(), 180, 2, failures, 10)

function step(state::ClaimToken)::Union{ClaimToken, HasNewToken, Failure}
    if time() > state.expiry || (time() - state.start_time)/1e6 > state.timeout # server-side or client-side timeout
        return GenericError("Timeout waiting for user to authenticate in browser.")
    end

    if state.failures > state.max_failures
        return GenericError("Too many failed attempts.")
    end

    sleep(state.poll_interval)

    output = IOBuffer()
    data = """{ "challenge": "$(state.challenge)", "response": "$(state.response)" }"""
    response = request(
        string(state.server, "/claimtoken"),
        method = "POST",
        input = IOBuffer(data),
        output = output,
        throw = false,
    )

    if response isa Response && response.status == 200
        body = try
            JSON.parse(String(take!(output)))
        catch err
            return ClaimToken(state.server, state.challenge, state.response, state.expiry, state.start_time, state.timeout, state.poll_interval, state.failures + 1, state.max_failures)
        end

        if haskey(body, "token")
            return HasNewToken(state.server, body["token"])
        elseif haskey(body, "expiry") # time at which the response/challenge pair will expire on the server
            return ClaimToken(state.server, state.challenge, state.response, body["expiry"], state.start_time, state.timeout, state.poll_interval, state.failures, state.max_failures)
        else
            return ClaimToken(state.server, state.challenge, state.response, state.expiry, state.start_time, state.timeout, state.poll_interval, state.failures + 1, state.max_failures)
        end
    else
        return HttpError(response)
    end

    return state
end

## errors

struct GenericError{T} <: Failure
    reason::T
end

abstract type HttpError <: Failure end

struct ClientError{T} <: HttpError
    reason::T
end

struct ServerError{T} <: HttpError
    reason::T
end

struct OtherHttpError{T} <: HttpError
    reason::T
end

function HttpError(response::Downloads.Response)::HttpError
    if 400 <= response.status < 500
        return ClientError(response)
    elseif 500 <= response.status < 600
        return ServerError(response)
    else
        return OtherHttpError(response)
    end
end

function HttpError(response::Downloads.RequestError)::HttpError
    return ClientError(response.message)
end

## utils
is_new_auth_mechanism() =
    isdefined(Pkg, :PlatformEngines) &&
    isdefined(Pkg.PlatformEngines, :get_server_dir) &&
    isdefined(Pkg.PlatformEngines, :register_auth_error_handler)

is_token_valid(toml) =
    get(toml, "id_token", nothing) isa AbstractString &&
    get(toml, "refresh_token", nothing) isa AbstractString &&
    get(toml, "refresh_url", nothing) isa AbstractString &&
    (get(toml, "expires_at", nothing) isa Union{Integer, AbstractFloat} ||
     get(toml, "expires", nothing) isa Union{Integer, AbstractFloat})

# This implementation of `get_server_dir` handles `domain:port` servers correctly (fixed on Pkg#master but not in older Julia versions).
function get_server_dir(url::AbstractString, server=Pkg.pkg_server())
    server === nothing && return
    url == server || startswith(url, "$server/") || return
    m = match(r"^\w+://(?:[^\\/@]+@)?([^\\/:]+)(?:$|/|:)", server)
    if m === nothing
        @warn "malformed Pkg server value" server
        return
    end
    joinpath(Pkg.depots1(), "servers", m.captures[1])
end

function token_path(url::AbstractString)
    if is_new_auth_mechanism()
        server_dir = get_server_dir(url)
        if server_dir !== nothing
            return joinpath(server_dir, "auth.toml")
        end
    end
    # older auth mechanism uses a different token location
    default = joinpath(Pkg.depots1(), "token.toml")
    get(ENV, "JULIA_PKG_TOKEN_PATH", default)
end

const OPEN_BROWSER_HOOK = Ref{Union{Base.Callable, Nothing}}(nothing)

function register_open_browser_hook(f::Base.Callable)
    if !hasmethod(f, Tuple{AbstractString})
        throw(ArgumentError("Browser hook must be a function taking a single URL string argument."))
    end
    OPEN_BROWSER_HOOK[] = f
end

function clear_open_browser_hook()
    OPEN_BROWSER_HOOK[] = nothing
end

function open_browser(url::AbstractString)
    @debug "opening auth in browser"
    printstyled(color = :yellow, bold = true,
        "Authentication required: please authenticate in browser.\n")
    printstyled(color = :yellow, """
    The authentication page should open in your browser automatically, but you may need to switch to the opened window or tab. If the authentication page is not automatically opened, you can authenticate by manually opening the following URL: """)
    printstyled(color = :light_blue, "$url\n")
    try
        if OPEN_BROWSER_HOOK[] !== nothing
            try
                OPEN_BROWSER_HOOK[](url)
                return true
            catch err
                @debug "error executing browser hook" exception=(err, catch_backtrace())
                return false
            end
        elseif Sys.iswindows()
            run(`cmd /c "start $url"`)
        elseif Sys.isapple()
            run(`open $url`)
        elseif Sys.islinux() || Sys.isbsd()
            run(`xdg-open $url`)
        end
    catch err
        @warn "There was a problem opening the authentication URL in a browser, please try opening this URL manually to authenticate." url, error = err
    end
    return true
end

"""
    install(server = nothing; maxcount = 3)

Install Pkg authentication hooks for `Pkg.pkg_server()`.

Will instead use `server` (and set the `JULIA_PKG_SERVER` environment variable accordingly) if given.
`maxcount` determines the number of retries.

Julia versions older than 1.4 do not support authentication hooks, so this function will force
authentication right away.
"""
function install(server = nothing; maxcount = 3)
    if server !== nothing
        ENV["JULIA_PKG_SERVER"] = server
    end
    server = Pkg.pkg_server()

    failed_auth_count = 0

    authenticate = (url, svr, err) -> begin
        ret = PkgAuthentication.authenticate(string(svr, "/auth"), tries = 2)
        if ret isa PkgAuthentication.Success
            failed_auth_count = 0
            @debug "Authentication successful."
        else
            failed_auth_count += 1
            if failed_auth_count >= maxcount
                printstyled(color = :red, bold = true, "\nAuthentication failed.\n\n")
                return true, false # handled, but Pkg shouldn't try again
            else
                printstyled(color = :yellow, bold = true, "\nAuthentication failed. Retrying...\n\n")
            end
        end
        return true, true # handled, and Pkg should try again now
    end

    register_auth_handler = (pkgserver::Union{Regex, AbstractString}) -> begin
        return Pkg.PlatformEngines.register_auth_error_handler(pkgserver, authenticate)
    end

    if PkgAuthentication.is_new_auth_mechanism()
        register_auth_handler(server)
    else
        # old Julia versions don't support auth hooks, so let's authenticate now and be done with it
        authenticate(server)
    end
end

end # module
