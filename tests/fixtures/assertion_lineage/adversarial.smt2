; Leading layout must contribute to absolute byte offsets.
(set-logic QF_UF)
(declare-sort U 0)
(declare-fun a () U)
(declare-fun b () U)
(declare-fun p () Bool)
(declare-fun q () Bool)
(declare-fun h (Bool) U)

; The macro creates one shared Bool-as-data term and one shared defining axiom.
(define-fun |m| () Bool (= (h (or p q)) a))

; The quoted let binding shadows the quoted macro and must not claim its lineage.
(assert (let ((|m| false)) (let ((x |m|)) (not x))))

; Identical roots retain distinct source identities and share macro auxiliaries.
(assert |m|)
(assert |m|)

; Term ITE elimination creates a result term plus two generated assertions.
(assert (= (ite p a b) a))
(check-sat)
