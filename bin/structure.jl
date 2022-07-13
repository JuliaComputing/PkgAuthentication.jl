using LightGraphs, PkgAuthentication, GraphPlot, Cairo, Compose

const bin_dir = @__DIR__
const root_dir = dirname(bin_dir)
const src_dir = joinpath(root_dir, "src")
const docs_dir = joinpath(root_dir, "docs")
const docs_assets_dir = joinpath(docs_dir, "assets")

file = joinpath(src_dir, "PkgAuthentication.jl")

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
draw(PNG(joinpath(docs_assets_dir, "structure.png"), 16cm, 16cm), plot)
