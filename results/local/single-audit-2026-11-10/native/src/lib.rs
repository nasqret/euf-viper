//! Standalone test harness, with no public solver API.
#![forbid(unsafe_code)]

#[cfg(all(test, not(feature = "fabric")))]
compile_error!("enable the default fabric feature to exercise the measured JSON serializer");

#[cfg(test)]
#[allow(dead_code)]
mod fabric {
    pub(crate) mod impact;
    pub(crate) mod partition;

    // The full CLI's tests may force a row representation. None means no
    // override; these fixtures select their test representation explicitly.
    pub(crate) mod cadical_up {
        pub(crate) mod policy_ablation_review {
            pub(crate) fn forced() -> Option<bool> {
                None
            }
        }
    }
}
