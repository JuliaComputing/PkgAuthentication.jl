@static if isdefined(Sys, :detectwsl)
    const detectwsl = Sys.detectwsl
else
    # Borrowed from Julia (MIT license)
    # https://github.com/JuliaLang/julia/blob/726c816b9590d748345fb615b76b685c79eafd0d/base/sysinfo.jl#L549-L555
    # https://github.com/JuliaLang/julia/pull/57069
    function detectwsl()
        # We use the same approach as canonical/snapd do to detect WSL
        Sys.islinux() && (
            isfile("/proc/sys/fs/binfmt_misc/WSLInterop")
            ||
            isdir("/run/WSL")
        )
    end
end
