using PkgAuthentication
using Test
using HTTP

import Pkg

include("util.jl")

@static if Base.VERSION < v"1.4-"
    @eval Pkg function pkg_server()::Union{String, Nothing}
        server = get(ENV, "JULIA_PKG_SERVER", "https://pkg.julialang.org")
        isempty(server) && return nothing
        startswith(server, r"\w+://") || (server = "https://$server")
        return rstrip(server, '/')
    end
end
@static if Base.VERSION < v"1.10-" # TODO: change this to "1.9-"
     @eval Pkg.PlatformEngines function get_server_dir(
        url :: AbstractString,
        server :: Union{AbstractString, Nothing} = pkg_server(),
    )
        server === nothing && return
        url == server || startswith(url, "$server/") || return
        m = match(r"^\w+://([^\\/]+)(?:$|/)", server)
        if m === nothing
            @warn "malformed Pkg server value" server
            return
        end
        isempty(Base.DEPOT_PATH) && return
        invalid_filename_chars = [':', '/', '<', '>', '"', '/', '\\', '|', '?', '*']
        dir = join(replace(c -> c in invalid_filename_chars ? '_' : c, collect(String(m.captures[1]))))
        return joinpath(depots1(), "servers", dir)
    end
 end

@testset "PkgAuthentication" begin
    with_temp_depot() do
        include("tests.jl")
    end
end
