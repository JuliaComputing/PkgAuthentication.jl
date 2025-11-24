function with_depot(f::F, depot_path::AbstractString) where {F <: Function}
    original_depot_path = copy(Base.DEPOT_PATH)
    empty!(Base.DEPOT_PATH)
    pushfirst!(Base.DEPOT_PATH, depot_path)

    active_depot = only(Pkg.depots())
    @info "The active depot is: $(active_depot)"

    return try
        f()
    finally
        empty!(Base.DEPOT_PATH)
        append!(Base.DEPOT_PATH, original_depot_path)
    end
end

function with_temp_depot(f::F) where {F <: Function}
    return mktempdir() do temp_depot
        with_depot(f, temp_depot)
    end
end

@static if Base.VERSION < v"1.4-"
    Base.@propagate_inbounds function only(x)
        i = iterate(x)
        @boundscheck if i === nothing
            throw(ArgumentError("Collection is empty, must contain exactly 1 element"))
        end
        (ret, state) = i::NTuple{2, Any}
        @boundscheck if iterate(x, state) !== nothing
            throw(ArgumentError("Collection has multiple elements, must contain exactly 1 element"))
        end
        return ret
    end
end
