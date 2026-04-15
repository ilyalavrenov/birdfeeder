//! birdfeeder is the CLI for the session API. Claim, inspect, expire and delete sessions, or check capacity, against
//! the dispatcher or a single roost. It also turns registry images into template blobs.

pub mod cli;
mod ociimage;
