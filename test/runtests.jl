using PkgAuthentication
using Test

@testset "PkgAuthentication" begin
    if VERSION < v"1.5"
        @test PkgAuthentication.is_new_auth_mechanism() == false
    else
        @test PkgAuthentication.is_new_auth_mechanism()
    end

    t = time()
    @test PkgAuthentication.authenticate("https://example.com") === nothing
    @test time() - t < PkgAuthentication.TIMEOUT

    t = time()
    @test PkgAuthentication.authenticate("https://juliahub.com/auth") === nothing
    @test time() - t >= PkgAuthentication.MANUAL_TIMEOUT
end
