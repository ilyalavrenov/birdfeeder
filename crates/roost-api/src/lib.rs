//! The session API roost and the dispatcher both serve, generated from `api/roost/v1/roost.proto`. Also has the claim
//! checks that both servers and the CLI run.

pub mod v1 {
    #![allow(clippy::all, clippy::pedantic, unused_qualifications)]
    include!(concat!(env!("OUT_DIR"), "/birdfeeder.roost.v1.rs"));
    include!(concat!(env!("OUT_DIR"), "/birdfeeder.roost.v1.serde.rs"));
}

mod validate;

pub use validate::{MAX_EXPIRES_AT_MS, RequestError, validate_claim, validate_expiry, validate_get, validate_list};
