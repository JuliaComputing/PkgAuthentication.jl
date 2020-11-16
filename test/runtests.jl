using PkgAuthentication
using Test
using HTTP

@testset "PkgAuthentication" begin
    if VERSION < v"1.5"
        @test PkgAuthentication.is_new_auth_mechanism() == false
    else
        @test PkgAuthentication.is_new_auth_mechanism()
    end

    serverurl = "http://localhost:8888"
    ENV["JULIA_PKG_SERVER"] = serverurl
    token = PkgAuthentication.token_path(serverurl)
    if ispath(token)
        @info "removing token"
        rm(token, force = true)
    end

    @testset "auth without server" begin
        success = PkgAuthentication.authenticate(serverurl)
        @test success isa PkgAuthentication.Failure
    end

    p = run(pipeline(`$(Base.julia_cmd()) --project=. $(joinpath(@__DIR__, "authserver.jl"))`, stdout="server_out.log", stderr="server_err.log"), wait=false)
    sleep(5)
    @show p

    @info "registering open-browser hook"
    PkgAuthentication.register_open_browser_hook(url -> HTTP.get(url))

    @testset "auth with running server" begin
        @info "testing inital auth"
        success = PkgAuthentication.authenticate(serverurl)

        @test success isa PkgAuthentication.Success
        @test success.token["expires_at"] > time()

        sleeptimer = ceil(Int, success.token["expires_at"]  - time() + 1)
        @info "sleep for $(sleeptimer)s (until refresh necessary)"
        sleep(sleeptimer)

        @info "testing auth refresh"
        success2 = PkgAuthentication.authenticate(serverurl)
        @test success2 isa PkgAuthentication.Success
        @test success2.token["expires_at"] > time()
        @test success2.token["refresh_token"] !== success.token["refresh_token"]
    end
    kill(p)
    println("output log:")
    println(read("server_out.log", String))
    println("error log:")
    println(read("server_err.log", String))
end
