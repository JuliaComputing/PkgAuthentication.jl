@testset "assert_dict_keys" begin
    @test_throws ErrorException PkgAuthentication.assert_dict_keys(Dict(), "foo"; msg="")
    @test PkgAuthentication.assert_dict_keys(Dict("foo" => 0), "foo"; msg="") === nothing
    @test_throws ErrorException PkgAuthentication.assert_dict_keys(Dict("bar" => 0), "foo"; msg="")

    @test PkgAuthentication.assert_dict_keys(Dict("foo" => 0, "bar" => 0), "foo", "bar"; msg="") === nothing
    @test PkgAuthentication.assert_dict_keys(Dict("foo" => 0), "foo", "bar"; msg="") === nothing
    @test PkgAuthentication.assert_dict_keys(Dict("bar" => 0), "foo", "bar"; msg="") === nothing
    @test_throws ErrorException PkgAuthentication.assert_dict_keys(Dict(), "foo", "bar"; msg="")
    @test_throws ErrorException PkgAuthentication.assert_dict_keys(Dict("baz" => 0), "foo", "bar"; msg="")
end
