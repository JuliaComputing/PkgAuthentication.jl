using PkgAuthentication
using Test
using HTTP

import Pkg

include("util.jl")

@testset "PkgAuthentication" begin
    with_temp_depot() do
        include("tests.jl")
    end
end
