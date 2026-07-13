(set-logic QF_UF)
(declare-sort |User
Sort| 0)
(declare-fun |left
value| () |User
Sort|)
(declare-fun |escaped\|bar| () |User
Sort|)
(declare-fun |unicode_lambda_λ| () |User
Sort|)
(declare-fun right () |User
Sort|)
(assert (! (= |left
value| right) :named |multi
line|))
(check-sat)
