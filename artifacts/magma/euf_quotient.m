// Minimal EUF quotient sanity artifact for Magma.

parent := [1, 2, 3, 4, 5, 6];

function Find(parent, x)
    y := x;
    while parent[y] ne y do
        y := parent[y];
    end while;
    return y;
end function;

procedure Union(~parent, a, b)
    ra := Find(parent, a);
    rb := Find(parent, b);
    if ra ne rb then
        parent[rb] := ra;
    end if;
end procedure;

Union(~parent, 1, 2);
Union(~parent, 3, 4);
assert Find(parent, 1) eq Find(parent, 2);
assert Find(parent, 3) eq Find(parent, 4);
assert Find(parent, 1) ne Find(parent, 3);
"magma-euf-quotient-ok";
