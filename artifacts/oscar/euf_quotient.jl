# Minimal EUF quotient sanity artifact for Julia/Oscar environments.

try
    import Oscar
    println("Oscar package loaded")
catch err
    println("Oscar package not available; continuing with Julia-only quotient check")
end

parent = collect(1:6)

function find_root!(parent, x)
    while parent[x] != x
        parent[x] = parent[parent[x]]
        x = parent[x]
    end
    return x
end

function union!(parent, a, b)
    ra = find_root!(parent, a)
    rb = find_root!(parent, b)
    if ra != rb
        parent[rb] = ra
    end
end

union!(parent, 1, 2)
union!(parent, 3, 4)
@assert find_root!(parent, 1) == find_root!(parent, 2)
@assert find_root!(parent, 3) == find_root!(parent, 4)
@assert find_root!(parent, 1) != find_root!(parent, 3)
println("julia-oscar-euf-quotient-ok")
