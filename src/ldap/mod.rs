//! Couche d'accès LDAP commune à tous les types d'annuaires.

pub mod codec;
pub mod conn;
pub mod dir;
pub mod dn;
pub mod entry;
pub mod flavor;
pub mod schema;
pub mod security;

pub use dir::Dir;
pub use entry::Entry;
pub use flavor::{Flavor, ServerInfo};
