(set-logic QF_UF)
(declare-sort U 0)
(declare-fun a () U)
(declare-fun b () U)
(assert
  (let ((x a))
    (let ((x b) (y x))
      (and (= x b) (= y a)))))
(check-sat)
