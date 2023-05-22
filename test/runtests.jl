using PkgAuthentication
using Test
using HTTP

import Pkg

include("util.jl")

@testset "PkgAuthentication" begin
    @testset "Utility functions" begin
        include("utilities_test.jl")
    end
    with_temp_depot() do
        include("tests.jl")
    end
end
