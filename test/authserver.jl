using HTTP, Random, JSON

const EXPIRY = 30
const CHALLENGE_EXPIRY = 10
const PORT = 8888

const ID_TOKEN = Random.randstring(100)
const TOKEN = Ref(Dict())

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
        "id_token" => ID_TOKEN,
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

    return HTTP.Response(200, JSON.json(Dict(
        "token" => TOKEN[]
    )))
end

function check_validity(req)
    payload = JSON.parse(String(req.body))

    return HTTP.Response(200, payload == TOKEN[])
end

router = HTTP.Router()
HTTP.register!(router, "POST", "/auth/challenge", challenge_handler)
HTTP.register!(router, "GET", "/auth/response", response_handler)
HTTP.register!(router, "POST", "/auth/claimtoken", claimtoken_handler)
HTTP.register!(router, "GET", "/auth/renew/token.toml/v2", renew_handler)
HTTP.register!(router, "POST", "/auth/isvalid", check_validity)

function run()
    println("starting server")
    HTTP.serve(router, "127.0.0.1", PORT)
    readline()
end

run()
