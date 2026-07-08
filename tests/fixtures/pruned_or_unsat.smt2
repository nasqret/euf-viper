(set-logic QF_UF)
(declare-sort U 0)
(declare-fun a () U)
(declare-fun b () U)
(declare-fun c () U)
(declare-fun d () U)
(assert
  (and
    (or (= a b) (= c d))
    (distinct a b)
    (distinct c d)))
(check-sat)
