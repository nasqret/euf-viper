# Minimal EUF quotient sanity artifact for SageMath.

parent = list(range(6))

def find(x):
    while parent[x] != x:
        parent[x] = parent[parent[x]]
        x = parent[x]
    return x

def union(a, b):
    ra, rb = find(a), find(b)
    if ra != rb:
        parent[rb] = ra

union(0, 1)
union(2, 3)
assert find(0) == find(1)
assert find(2) == find(3)
assert find(0) != find(2)
print("sage-euf-quotient-ok")
