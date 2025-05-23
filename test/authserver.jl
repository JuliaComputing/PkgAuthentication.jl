using HTTP, Random, JSON
import Pkg: TOML

const EXPIRY = 30
const CHALLENGE_EXPIRY = 10
const PORT = 8888
const LEGACY_MODE = 1
const DEVICE_FLOW_MODE = 2

const ID_TOKEN = Random.randstring(100)
const TOKEN = Ref(Dict())
const MODE = Ref(LEGACY_MODE)

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
        "id_token" => "full-" * ID_TOKEN,
        "access_token" => "full-" * ID_TOKEN,
        "refresh_token" => refresh_token,
        "refresh_url" => "http://localhost:$(PORT)/auth/renew/token.toml/v2/",
        "expires_in" => EXPIRY,
        "expires_at" => round(Int, time()) + EXPIRY
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
        return HTTP.Response(200, JSON.json(Dict(
            "token" => TOKEN[]
        )))
    else
        expires_in = round(Int, challenge_timeout[payload["challenge"]] - time())
        @show expires_in
        return HTTP.Response(200, JSON.json(Dict(
            "expiry" => expires_in
        )))
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
    TOKEN[]["id_token"] = "refresh-" * ID_TOKEN
    TOKEN[]["access_token"] = "refresh-" * ID_TOKEN

    return HTTP.Response(200, sprint(TOML.print, TOKEN[]))
end

function check_validity(req)
    payload = JSON.parse(String(req.body))

    return HTTP.Response(200, payload == TOKEN[])
end

function set_mode_legacy(req)
    MODE[] = LEGACY_MODE
    return HTTP.Response(200)
end

function set_mode_device(req)
    MODE[] = DEVICE_FLOW_MODE
    return HTTP.Response(200)
end

function auth_configuration(req)
    if MODE[] == LEGACY_MODE
        return HTTP.Response(200)
    else
        return HTTP.Response(
            200,
            """ {
                "auth_flows": ["classic", "device"],
                "device_token_refresh_url": "http://localhost:$PORT/auth/renew/token.toml/device/",
                "device_authorization_endpoint": "http://localhost:$PORT/auth/device/code",
                "device_token_endpoint": "http://localhost:$PORT/auth/token"
            } """,
        )
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
    TOKEN[]["access_token"] = "device-$ID_TOKEN"
    TOKEN[]["token_type"] = "bearer"
    TOKEN[]["expires_in"] = EXPIRY
    TOKEN[]["refresh_token"] = refresh_token
    TOKEN[]["id_token"] = "device-$ID_TOKEN"
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
HTTP.register!(router, "POST", "/set_mode/legacy", set_mode_legacy)
HTTP.register!(router, "POST", "/set_mode/device", set_mode_device)

function run()
    println("starting server")
    HTTP.serve(router, "127.0.0.1", PORT)
    readline()
end

run()
