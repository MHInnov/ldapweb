//! Pages et fragments HTML, regroupés par module fonctionnel (équivalents RSAT).

pub mod attrs;
pub mod dashboard;
pub mod dhcp;
pub mod directory;
pub mod dns;
pub mod domain;
pub mod gpo;
pub mod kerberos;
pub mod objects;
pub mod pki;
pub mod search;

use crate::web::auth::Ctx;
use askama::Template;

/// Page générique : titre, sous-titre, actions et contenu HTML pré-rendus.
#[derive(Template)]
#[template(path = "generic.html")]
pub struct Generic {
    pub ctx: Ctx,
    pub title: String,
    pub subtitle: String,
    pub actions: String,
    pub body: String,
}

/// Dialogue de formulaire générique.
#[derive(Template)]
#[template(path = "dlg_form.html")]
pub struct DlgForm {
    pub size: &'static str,
    pub action: String,
    pub swap: &'static str,
    pub target: String,
    pub icon: &'static str,
    pub title: String,
    pub body: String,
    pub submit: String,
    pub cancel: &'static str,
}

impl DlgForm {
    pub fn new(
        title: impl Into<String>,
        icon: &'static str,
        action: impl Into<String>,
        body: String,
        submit: &str,
    ) -> Self {
        DlgForm {
            size: "",
            action: action.into(),
            swap: "none",
            target: String::new(),
            icon,
            title: title.into(),
            body,
            submit: submit.into(),
            cancel: "Annuler",
        }
    }
}
