using LightGraphs, PkgAuthentication, GraphPlot, Cairo, Compose

file = joinpath(dirname(@__DIR__), "src", "PkgAuthentication.jl")

g = SimpleDiGraph()
lines = readlines(file)

vertices = string.(nameof.(subtypes(PkgAuthentication.State)))
for vertex in vertices
    add_vertex!(g)
end

for line in lines
    m = match(r"^function step\(state::(.+?)\)::Union{(.+?)}$", line)
    if m !== nothing
        for target in strip.(split(m[2], ','))
            add_edge!(g, findfirst(==(m[1]), vertices), findfirst(==(target), vertices))
        end
    end
end
plot = gplot(g, nodelabel=vertices, linetype="curve")
draw(PNG(joinpath(@__DIR__, "structure.png"), 16cm, 16cm), plot)
