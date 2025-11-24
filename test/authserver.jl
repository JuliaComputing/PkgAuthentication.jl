using HTTP, Random, JSON
import Pkg: TOML

const EXPIRY = 30
const CHALLENGE_EXPIRY = 10
const PORT = 8888
@enum AuthFlowMode CLASSIC_MODE DEVICE_FLOW_MODE DEVICE_FLOW_NO_SCOPE_MODE

const TOKEN = Ref(Dict())
const MODE = Ref(CLASSIC_MODE)

const REQUEST_SET = Set()
# this counts the number of distinct authentication requests made against the server
function id_token(key)
    push!(REQUEST_SET, key)
    token = length(REQUEST_SET)
    return string(token)
end

challenge_response_map = Dict()
challenge_timeout = Dict()
response_challenge_map = Dict()
function challenge_handler(req)
    println("challenge_handler")
    challenge = String(req.body)
    response = Random.randstring(64)
    challenge_timeout[challenge] = time() + CHALLENGE_EXPIRY

    response_challenge_map[response] = challenge

    return HTTP.Response(200, response)
end

refresh_token_map = Dict()
function response_handler(req)
    println("response_handler")

    response = HTTP.URIs.URI(req.target).query
    @show response
    if haskey(response_challenge_map, response)
        challenge = response_challenge_map[response]
        @show challenge
        challenge_response_map[challenge] = response
    else
        return HTTP.Response(400)
    end

    refresh_token = Random.randstring(10)
    TOKEN[] = Dict(
        "user_name" => "firstname lastname",
        "user_email" => "user@email.com",
        "id_token" => "full-" * id_token(response),
        "access_token" => "full-" * id_token(response),
        "refresh_token" => refresh_token,
        "refresh_url" => "http://localhost:$(PORT)/auth/renew/token.toml/v2/",
        "expires_in" => EXPIRY,
        "expires_at" => round(Int, time()) + EXPIRY,
    )

    @show response

    return HTTP.Response(200)
end

function claimtoken_handler(req)
    println("claimtoken_handler")
    payload = JSON.parse(String(req.body))
    @show payload
    @show challenge_response_map
    if haskey(challenge_response_map, payload["challenge"]) &&
            challenge_response_map[payload["challenge"]] == payload["response"]

        delete!(challenge_response_map, payload["challenge"])
        delete!(response_challenge_map, payload["response"])
        @show JSON.json(TOKEN[])
        return HTTP.Response(
            200, JSON.json(
                Dict(
                    "token" => TOKEN[]
                )
            )
        )
    else
        expires_in = round(Int, challenge_timeout[payload["challenge"]] - time())
        @show expires_in
        return HTTP.Response(
            200, JSON.json(
                Dict(
                    "expiry" => expires_in
                )
            )
        )
    end

end

function renew_handler(req)
    println("renew_handler")
    auth = HTTP.header(req, "Authorization")
    @show auth
    refresh_token = match(r"Bearer (.+)", auth)[1]

    @assert refresh_token == TOKEN[]["refresh_token"]

    TOKEN[]["refresh_token"] = Random.randstring(10)
    TOKEN[]["expires_at"] = ceil(Int, time() + EXPIRY)
    TOKEN[]["id_token"] = "refresh-" * id_token(auth)
    TOKEN[]["access_token"] = "refresh-" * id_token(auth)

    return HTTP.Response(200, sprint(TOML.print, TOKEN[]))
end

function check_validity(req)
    payload = JSON.parse(String(req.body))

    return HTTP.Response(200, payload == TOKEN[])
end

function set_mode(req)
    global MODE
    # We want to grab the last path element of the '/set_mode/{mode}' URI
    mode = last(split(HTTP.URIs.URI(req.target).path, '/'))
    if mode == "classic"
        MODE[] = CLASSIC_MODE
    elseif mode == "device"
        MODE[] = DEVICE_FLOW_MODE
    elseif mode == "device-no-scope"
        MODE[] = DEVICE_FLOW_NO_SCOPE_MODE
    else
        return HTTP.Response(400, "Invalid Mode $(mode)")
    end
    return HTTP.Response(200)
end

function auth_configuration(req)
    global MODE
    if MODE[] == CLASSIC_MODE
        # classic mode could also return `auth_flows = ["classic"]`, but we choose to test
        # the legacy case where the configuration is not implemented at all (which also
        # implies the classic mode).
        return HTTP.Response(501, "Not Implemented")
    else
        body = Dict(
            "auth_flows" => ["classic", "device"],
            "device_token_refresh_url" => "http://localhost:$PORT/auth/renew/token.toml/device/",
            "device_authorization_endpoint" => "http://localhost:$PORT/auth/device/code",
            "device_token_endpoint" => "http://localhost:$PORT/auth/token",
        )
        # device_token_scope omitted in DEVICE_FLOW_NO_SCOPE_MODE
        if MODE[] == DEVICE_FLOW_MODE
            body["device_token_scope"] = "openid"
        end
        return HTTP.Response(200, JSON.json(body))
    end
end

device_code_user_code_map = Dict{String, Any}()
user_code_device_code_map = Dict{String, Any}()
authenticated = Dict{String, Any}()
function auth_device_code(req)
    device_code = randstring(64)
    user_code = randstring(8)
    device_code_user_code_map[device_code] = user_code
    user_code_device_code_map[user_code] = device_code
    return HTTP.Response(
        200,
        """ {
            "device_code": "$device_code",
            "user_code": "$user_code",
            "verification_uri_complete": "http://localhost:$PORT/auth/device?user_code=$user_code",
            "expires_in": $CHALLENGE_EXPIRY
        } """,
    )
end

function auth_device(req)
    params = HTTP.queryparams(HTTP.URIs.URI(req.target).query)
    user_code = get(params, "user_code", "")
    device_code = get(user_code_device_code_map, user_code, nothing)
    if device_code === nothing
        return HTTP.Response(400)
    end
    authenticated[device_code] = true
    refresh_token = Random.randstring(10)
    TOKEN[]["access_token"] = "device-$(id_token(user_code))"
    TOKEN[]["token_type"] = "bearer"
    TOKEN[]["expires_in"] = EXPIRY
    TOKEN[]["refresh_token"] = refresh_token
    TOKEN[]["id_token"] = "device-$(id_token(user_code))"
    return HTTP.Response(200)
end

function auth_token(req)
    p = split(String(req.body), "&")
    d = Dict{String, Any}()
    for l in p
        kv = split(String(l), "=")
        d[String(kv[1])] = String(kv[2])
    end
    device_code = get(d, "device_code", nothing)
    if device_code === nothing || !get(authenticated, device_code, false)
        return HTTP.Response(401)
    end
    return HTTP.Response(200, JSON.json(TOKEN[]))
end

router = HTTP.Router()
HTTP.register!(router, "POST", "/auth/challenge", challenge_handler)
HTTP.register!(router, "GET", "/auth/response", response_handler)
HTTP.register!(router, "POST", "/auth/claimtoken", claimtoken_handler)
HTTP.register!(router, "GET", "/auth/renew/token.toml/v2", renew_handler)
HTTP.register!(router, "POST", "/auth/isvalid", check_validity)
HTTP.register!(router, "GET", "/auth/configuration", auth_configuration)
HTTP.register!(router, "POST", "/auth/device/code", auth_device_code)
HTTP.register!(router, "GET", "/auth/device", auth_device)
HTTP.register!(router, "POST", "/auth/token", auth_token)
HTTP.register!(router, "GET", "/auth/renew/token.toml/device", renew_handler)
# We run tests on Julia 1.3-1.5, so we need to also support HTTP 0.9 server.
# Unfortunately, HTTP 0.9 does not support variables in route paths, so
# we can't do
#
#  HTTP.register!(router, "POST", "/set_mode/{mode}", set_mode)
#
# So we hack around this.
for mode in ["classic", "device", "device-no-scope"]
    HTTP.register!(router, "POST", "/set_mode/$(mode)", set_mode)
end

function run()
    println("starting server")
    HTTP.serve(router, "127.0.0.1", PORT)
    return readline()
end

run()
