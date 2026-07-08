(set-logic QF_UF)
(declare-sort U 0)
(declare-fun x0 () U)
(declare-fun x1 () U)
(declare-fun y0 () U)
(declare-fun z0 () U)
(assert
  (and
    (or (and (= x0 y0) (= y0 x1))
        (and (= x0 z0) (= z0 x1)))
    (distinct x0 x1)))
(check-sat)
