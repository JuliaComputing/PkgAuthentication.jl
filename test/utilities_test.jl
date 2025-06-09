@testset "assert_dict_keys" begin
    @test_throws ErrorException PkgAuthentication.assert_dict_keys(Dict(), "foo"; msg="")
    @test PkgAuthentication.assert_dict_keys(Dict("foo" => 0), "foo"; msg="") === nothing
    @test_throws ErrorException PkgAuthentication.assert_dict_keys(Dict("bar" => 0), "foo"; msg="")

    @test PkgAuthentication.assert_dict_keys(Dict("foo" => 0, "bar" => 0), "foo", "bar"; msg="") === nothing
    @test PkgAuthentication.assert_dict_keys(Dict("foo" => 0), "foo", "bar"; msg="") === nothing
    @test PkgAuthentication.assert_dict_keys(Dict("bar" => 0), "foo", "bar"; msg="") === nothing
    @test_throws ErrorException PkgAuthentication.assert_dict_keys(Dict(), "foo", "bar"; msg="")
    @test_throws ErrorException PkgAuthentication.assert_dict_keys(Dict("baz" => 0), "foo", "bar"; msg="")

    @test PkgAuthentication.detectwsl() isa Bool
end

@testset "device_token_request_body" begin
    @test String(take!(PkgAuthentication.device_token_request_body(client_id="foo"))) == "client_id=foo"
    @test String(take!(PkgAuthentication.device_token_request_body(client_id="foo", scope="bar"))) == "client_id=foo&scope=bar"
    @test String(take!(PkgAuthentication.device_token_request_body(client_id="foo", device_code="bar"))) == "client_id=foo&device_code=bar"
    @test String(take!(PkgAuthentication.device_token_request_body(client_id="foo", grant_type="bar"))) == "client_id=foo&grant_type=bar"
    @test String(take!(PkgAuthentication.device_token_request_body(client_id="foo", scope="bar", device_code="baz", grant_type="qux"))) == "client_id=foo&scope=bar&device_code=baz&grant_type=qux"
    @test String(take!(PkgAuthentication.device_token_request_body(client_id="foo", scope=nothing, device_code=nothing, grant_type=nothing))) == "client_id=foo"
end
