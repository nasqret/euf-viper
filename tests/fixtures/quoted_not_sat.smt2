(set-logic QF_UF)
(declare-fun |not| (Bool) Bool)
(assert (|not| true))
(check-sat)
