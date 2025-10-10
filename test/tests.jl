@static if VERSION >= v"1.5-"
    @test PkgAuthentication.is_new_auth_mechanism()
else
    @test !PkgAuthentication.is_new_auth_mechanism()
end

const test_pkg_server = "http://localhost:8888/"
ENV["JULIA_PKG_SERVER"] = test_pkg_server

# Keep in mind that we are running the tests inside a temporary depot that we will
# destroy at the end of the tests. Therefore, it's perfectly fine for us to do stuff
# like delete the `servers` directory.
function delete_token()
    token_path = PkgAuthentication.token_path(test_pkg_server)
    servers_dir = joinpath(only(Pkg.depots()), "servers")
    @info "" token_path
    rm(token_path; force=true, recursive=true)
    @info "" servers_dir
    rm(servers_dir; force=true, recursive=true)
end

# Helper function to do the GET against /auth/configuration
# Note: having a / at the end of the first argument of NoAuthentication
# will break the HTTP call.
get_auth_configuration() = PkgAuthentication.get_auth_configuration(
    PkgAuthentication.NoAuthentication(rstrip(test_pkg_server, '/'), "auth")
)

@testset "auth without server" begin
    delete_token()
    success = PkgAuthentication.authenticate(test_pkg_server)
    @test success isa PkgAuthentication.Failure
end

authserver_file = joinpath(@__DIR__, "authserver.jl")
@info "Starting the test server"
cmd = `$(Base.julia_cmd())  $(authserver_file)`
env2 = copy(ENV)
env2["JULIA_PROJECT"] = Base.active_project()
p = run(pipeline(setenv(cmd, env2); stdout=stdout, stderr=stdout); wait=false)
atexit(() -> kill(p))
sleep(10)

@info "registering open-browser hook"
PkgAuthentication.register_open_browser_hook(url -> HTTP.get(url))

@testset "auth with running server" begin
    delete_token()

    @info "testing inital auth"
    success = PkgAuthentication.authenticate(test_pkg_server)

    @test success isa PkgAuthentication.Success
    @test success.token["expires_at"] > time()
    @test startswith(success.token["id_token"], "full-")
    @test !occursin("id_token", sprint(show, success))

    sleeptimer = ceil(Int, success.token["expires_at"] - time() + 1)
    @info "sleep for $(sleeptimer)s (until refresh necessary)"
    sleep(sleeptimer)

    @info "testing auth refresh"
    success2 = PkgAuthentication.authenticate(test_pkg_server)
    @test success2 isa PkgAuthentication.Success
    @test !occursin("id_token", sprint(show, success2))
    @test success2.token["expires_at"] > time()
    @test success2.token["refresh_token"] !== success.token["refresh_token"]
    @test startswith(success2.token["id_token"], "refresh-")
end

@testset "auth with running server (device flow)" begin
    delete_token()
    HTTP.post(joinpath(test_pkg_server, "set_mode/device"))

    # Double check that the test server is responding with the correct
    # configuration information.
    config = get_auth_configuration()
    @test haskey(config, "device_token_scope")
    @test config["device_token_scope"] == "openid"

    @info "testing inital auth"
    success = PkgAuthentication.authenticate(test_pkg_server)

    @test success isa PkgAuthentication.Success
    @test success.token["expires_at"] > time()
    @test startswith(success.token["id_token"], "device-")
    @test !occursin("id_token", sprint(show, success))

    sleeptimer = ceil(Int, success.token["expires_at"] - time() + 1)
    @info "sleep for $(sleeptimer)s (until refresh necessary)"
    sleep(sleeptimer)

    @info "testing auth refresh"
    success2 = PkgAuthentication.authenticate(test_pkg_server)
    @test success2 isa PkgAuthentication.Success
    @test !occursin("id_token", sprint(show, success2))
    @test success2.token["expires_at"] > time()
    @test success2.token["refresh_token"] !== success.token["refresh_token"]
    @test startswith(success2.token["id_token"], "refresh-")

    HTTP.post(joinpath(test_pkg_server, "set_mode/classic"))
end

@testset "auth with running server (device flow; no scope)" begin
    delete_token()
    HTTP.post(joinpath(test_pkg_server, "set_mode/device-no-scope"))

    config = get_auth_configuration()
    @test !haskey(config, "device_token_scope")

    @info "testing inital auth"
    success = PkgAuthentication.authenticate(test_pkg_server)

    @test success isa PkgAuthentication.Success
    @test success.token["expires_at"] > time()
    @test startswith(success.token["id_token"], "device-")
    @test !occursin("id_token", sprint(show, success))

    sleeptimer = ceil(Int, success.token["expires_at"] - time() + 1)
    @info "sleep for $(sleeptimer)s (until refresh necessary)"
    sleep(sleeptimer)

    @info "testing auth refresh"
    success2 = PkgAuthentication.authenticate(test_pkg_server)
    @test success2 isa PkgAuthentication.Success
    @test !occursin("id_token", sprint(show, success2))
    @test success2.token["expires_at"] > time()
    @test success2.token["refresh_token"] !== success.token["refresh_token"]
    @test startswith(success2.token["id_token"], "refresh-")

    HTTP.post(joinpath(test_pkg_server, "set_mode/classic"))
end


@testset "PkgAuthentication.install" begin
    delete_token()

    result = PkgAuthentication.install(test_pkg_server)
    @test result isa PkgAuthentication.Uninstall
    @static if PkgAuthentication.is_new_auth_mechanism()
        # On Julia 1.4+, the return value of `PkgAuthentication.install` will be
        # the return value from the `Pkg.PlatformEngines.register_auth_error_handler`
        # call. `Pkg.PlatformEngines.register_auth_error_handler` returns a zero-arg function
        # that can be called to deregister the handler.
        @test result.f isa Function
    else
        # On Julia <1.4, the return value of `PkgAuthentication.install` will be
        # the return value from the `PkgAuthentication.authenticate` call.
        @test isnothing(result.f)
    end

    @testset "PkgAuthentication.Uninstall" begin
        let u = PkgAuthentication.Uninstall(nothing)
            @test u() === nothing
        end
        let count = 1
            u = PkgAuthentication.Uninstall(() -> (count += 1; nothing))
            @test count == 1
            @test u() === nothing
            @test count == 2
            @test u() === nothing
            @test count == 3
        end
    end
end

@testset "Testing the `auth_handler` generated by `generate_auth_handler`" begin
    delete_token()

    maxcount = 5
    auth_handler = PkgAuthentication.generate_auth_handler(maxcount)
    url = "https://julialang.org/"
    err = "no-auth-file"
    result = auth_handler(url, test_pkg_server, err)
    @test result == (true, true)
end

kill(p)
