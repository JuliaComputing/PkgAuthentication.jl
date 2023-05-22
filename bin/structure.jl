# This script generates the `docs/internals.md` file, that mainly contains the
# state machine diagram that we can automatically generate from the code.
import PkgAuthentication
import InteractiveUtils, Markdown, TextWrap

# Rather than generating the file directly, we'll write the output to a buffer
# first, so that we wouldn't end up with a partial file if there is some error.
buffer = let buffer = IOBuffer(write=true)
    write(buffer, """
    # Internal implementation notes

    The authentication control flow is implemented as the following state machine, starting from the `NeedAuthentication` state (or `NoAuthentication` if `force=true` is passed to `authenticate`), and finishing in either `Success` or `Failure`.

    ```mermaid
    ---
    title: PkgAuthentication state machine diagram
    ---

    stateDiagram-v2
        direction LR

        [*] --> NeedAuthentication
        [*] --> NoAuthentication
    """)

    # We'll loop over
    all_targets = Dict{String,Vector{String}}()
    ignore_errors = (
        PkgAuthentication.Failure, PkgAuthentication.Success
    )
    for line in readlines(pathof(PkgAuthentication))
        m = match(r"^function step\(state::(.+?)\)::Union{(.+?)}$", line)
        if m !== nothing
            all_targets[m[1]] = strip.(split(m[2], ','))
        end
    end
    for state in sort(InteractiveUtils.subtypes(PkgAuthentication.State), by=string)
        println(buffer)
        state_str = string(nameof(state))
        targets = get(all_targets, state_str, String[])
        if isempty(targets) && (state ∉ ignore_errors)
            @warn "Empty targets list for $state"
        elseif !isempty(targets)
            for target in targets
                println(buffer, "    $(state_str) --> $(target)")
            end
        end
        # Extract the docstring and put it into a mermaid note
        try
            docstr::Markdown.MD = Base.Docs.doc(state)
            docstr_text = docstr.meta[:results][1].text[1]
            println(buffer, "    note right of $(state_str)")
            TextWrap.print_wrapped(
                buffer, docstr_text, width=65,
                initial_indent = 8, subsequent_indent = 8,
            )
            println(buffer)
            println(buffer, "    end note")
        catch e
            if state ∉ ignore_errors
                @error "Invalid docstring for $state" exception = (e, catch_backtrace())
            end
        end
    end

    write(buffer, """
        Success --> [*]
        Failure --> [*]
    ```

    > **Note** This file is automatically generated by the `bin/structure.jl` script.
    """)

    take!(buffer)
end

# Actually write the diagram to file now that we have successfully managed
# to fully generate it.
let docs_dir = joinpath(dirname(@__DIR__), "docs")
    if !isdir(docs_dir)
        ispath(docs_dir) && error("$docs_dir exists, but is not a directory")
        mkpath(docs_dir)
    end
    internals_md = joinpath(docs_dir, "internals.md")
    isfile(internals_md) && @warn "Overwriting: $(internals_md)"
    write(internals_md, buffer)
end
