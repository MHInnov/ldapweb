//! « Utilisateurs et ordinateurs » (équivalent ADUC) et explorateur LDAP brut
//! (équivalent ADSI Edit).

use crate::directory::kinds::{Kind, LIST_ATTRS, state_badges};
use crate::directory::{container_filter, list_filter};
use crate::error::AppResult;
use crate::ldap::{Dir, Entry, dn};
use crate::web::auth::{Auth, Ctx};
use crate::web::html::{render, url};
use askama::Template;
use axum::extract::Query;
use axum::response::{Html, IntoResponse, Response};
use ldap3::Scope;
use serde::Deserialize;

#[derive(Deserialize, Default)]
pub struct DnQ {
    #[serde(default)]
    pub dn: String,
    #[serde(default)]
    pub q: String,
}

pub struct TreeNode {
    pub dn: String,
    pub name: String,
    pub icon: &'static str,
    pub leaf: bool,
    pub open: bool,
    pub current: bool,
    pub children: String,
    pub children_url: String,
    pub href: String,
    pub click_url: String,
    pub click_target: String,
    pub click_swap: String,
    pub push_url: String,
}

#[derive(Template)]
#[template(path = "tree_nodes.html")]
pub struct TreeNodes {
    pub nodes: Vec<TreeNode>,
    pub show_empty: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum TreeMode {
    Aduc,
    Browse,
}

fn make_node(e: &Entry, mode: TreeMode, base: &str) -> TreeNode {
    let k = Kind::of(e);
    let name = if dn::eq(&e.dn, base) && mode == TreeMode::Aduc {
        let d = dn::dc_to_domain(&e.dn);
        if d.is_empty() { e.rdn_name() } else { d }
    } else if mode == TreeMode::Browse {
        dn::rdn(&e.dn)
    } else {
        e.rdn_name()
    };
    let leaf = matches!(e.str("hasSubordinates").as_deref(), Some("FALSE"));
    let du = url(&e.dn);
    match mode {
        TreeMode::Aduc => TreeNode {
            dn: e.dn.clone(),
            name,
            icon: k.icon(),
            leaf,
            open: false,
            current: false,
            children: String::new(),
            children_url: format!("/dir/tree?dn={du}"),
            href: format!("/dir?dn={du}"),
            click_url: format!("/dir/list?dn={du}"),
            click_target: "#list".into(),
            click_swap: "outerHTML".into(),
            push_url: format!("/dir?dn={du}"),
        },
        TreeMode::Browse => TreeNode {
            dn: e.dn.clone(),
            name,
            icon: k.icon(),
            leaf,
            open: false,
            current: false,
            children: String::new(),
            children_url: format!("/browse/tree?dn={du}"),
            href: format!("/browse?dn={du}"),
            click_url: format!("/obj/tab?dn={du}&tab=browse"),
            click_target: "#browse-detail".into(),
            click_swap: "innerHTML".into(),
            push_url: format!("/browse?dn={du}"),
        },
    }
}

async fn children(dir: &mut Dir, parent: &str, filter: &str, mode: TreeMode) -> AppResult<Vec<TreeNode>> {
    let attrs = ["objectClass", "cn", "ou", "dc", "name", "hasSubordinates"];
    let (mut v, _) = dir.search_paged(parent, Scope::OneLevel, filter, &attrs, 2000).await?;
    v.sort_by(|a, b| {
        Kind::of(a)
            .order()
            .cmp(&Kind::of(b).order())
            .then(a.rdn_name().to_lowercase().cmp(&b.rdn_name().to_lowercase()))
    });
    let base = dir.base().to_string();
    Ok(v.iter().map(|e| make_node(e, mode, &base)).collect())
}

fn tree_filter(a: &Auth) -> String {
    container_filter(a.s.info.flavor, a.s.profile.posix.tree_container_classes.as_ref(), a.s.is_advanced())
}

/// Arborescence pré-dépliée jusqu'à `target`.
async fn tree_to(dir: &mut Dir, roots: Vec<Entry>, target: &str, filter: &str, mode: TreeMode) -> AppResult<String> {
    let base = dir.base().to_string();
    let mut nodes: Vec<TreeNode> = roots.iter().map(|e| make_node(e, mode, &base)).collect();
    for n in nodes.iter_mut() {
        if dn::is_under(target, &n.dn) {
            n.open = true;
            n.current = dn::eq(target, &n.dn);
            n.children = Box::pin(expand(dir, &n.dn, target, filter, mode)).await?;
        }
    }
    Ok(TreeNodes { nodes, show_empty: false }.render()?)
}

async fn expand(dir: &mut Dir, at: &str, target: &str, filter: &str, mode: TreeMode) -> AppResult<String> {
    let mut nodes = children(dir, at, filter, mode).await?;
    for n in nodes.iter_mut() {
        if dn::is_under(target, &n.dn) {
            n.current = dn::eq(target, &n.dn);
            if !n.current || mode == TreeMode::Aduc {
                n.open = true;
                n.children = Box::pin(expand(dir, &n.dn, target, filter, mode)).await?;
            }
        }
    }
    Ok(TreeNodes { nodes, show_empty: true }.render()?)
}

pub async fn tree(a: Auth, Query(q): Query<DnQ>) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let f = tree_filter(&a);
    let nodes = children(&mut dir, &q.dn, &f, TreeMode::Aduc).await?;
    render(&TreeNodes { nodes, show_empty: true })
}

pub struct Row {
    pub dn: String,
    pub name: String,
    pub icon: &'static str,
    pub kind: &'static str,
    pub description: String,
    pub login: String,
    pub badges: Vec<(&'static str, &'static str)>,
    pub open_url: String,
    pub open_target: &'static str,
    pub open_swap: &'static str,
}

#[derive(Template)]
#[template(path = "dir_list.html")]
struct ListTpl {
    dn: String,
    q: String,
    crumbs: Vec<(String, String)>,
    rows: Vec<Row>,
    truncated: bool,
    is_ad: bool,
}

pub fn row_of(e: &Entry, flavor: crate::ldap::Flavor) -> Row {
    let k = Kind::of(e);
    let login = if flavor.is_ad() { e.s("sAMAccountName") } else { e.s("uid") };
    let du = url(&e.dn);
    let (open_url, open_target, open_swap) = if k.is_container() {
        (format!("/dir/list?dn={du}"), "#list", "outerHTML")
    } else {
        (format!("/obj/props?dn={du}"), "#modal", "innerHTML")
    };
    let description = match k {
        Kind::Computer => {
            let d = e.s("description");
            if d.is_empty() { e.s("operatingSystem") } else { d }
        }
        _ => e.s("description"),
    };
    Row {
        dn: e.dn.clone(),
        name: e.rdn_name(),
        icon: k.icon(),
        kind: k.label(),
        description,
        login,
        badges: state_badges(e, flavor),
        open_url,
        open_target,
        open_swap,
    }
}

async fn list_html(a: &Auth, dir: &mut Dir, container: &str, q: &str) -> AppResult<String> {
    let flavor = dir.info.flavor;
    let filter = list_filter(flavor, a.s.is_advanced(), q);
    let limit = dir.profile.max_list_entries;
    let (mut v, truncated) = dir.search_paged(container, Scope::OneLevel, &filter, LIST_ATTRS, limit).await?;
    v.sort_by(|x, y| {
        Kind::of(x)
            .order()
            .cmp(&Kind::of(y).order())
            .then(x.rdn_name().to_lowercase().cmp(&y.rdn_name().to_lowercase()))
    });
    let rows = v.iter().map(|e| row_of(e, flavor)).collect();
    let base = dir.base().to_string();
    Ok(ListTpl {
        dn: container.to_string(),
        q: q.to_string(),
        crumbs: dn::breadcrumb(container, &base),
        rows,
        truncated,
        is_ad: flavor.is_ad(),
    }
    .render()?)
}

pub async fn list(a: Auth, Query(q): Query<DnQ>) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let container = if q.dn.is_empty() { dir.base().to_string() } else { q.dn.clone() };
    Ok(Html(list_html(&a, &mut dir, &container, &q.q).await?).into_response())
}

#[derive(Template)]
#[template(path = "dir.html")]
struct DirPage {
    ctx: Ctx,
    tree: String,
    list: String,
}

pub async fn page(a: Auth, Query(q): Query<DnQ>) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let base = dir.base().to_string();
    let target = if q.dn.is_empty() || !dn::is_under(&q.dn, &base) { base.clone() } else { q.dn.clone() };
    let root = dir.read_req(&base, &["objectClass", "dc", "ou", "o", "cn", "name"]).await?;
    let f = tree_filter(&a);
    let tree = tree_to(&mut dir, vec![root], &target, &f, TreeMode::Aduc).await?;
    let list = list_html(&a, &mut dir, &target, &q.q).await?;
    render(&DirPage { ctx: a.ctx("dir"), tree, list })
}

// ------------------------------------------------------------------ explorateur LDAP

#[derive(Template)]
#[template(path = "browse.html")]
struct BrowsePage {
    ctx: Ctx,
    tree: String,
    detail: String,
}

pub async fn browse_tree(a: Auth, Query(q): Query<DnQ>) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let nodes = children(&mut dir, &q.dn, "(objectClass=*)", TreeMode::Browse).await?;
    render(&TreeNodes { nodes, show_empty: true })
}

pub async fn browse(a: Auth, Query(q): Query<DnQ>) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let info = dir.info.clone();
    let mut roots = Vec::new();
    let mut ncs = info.naming_contexts.clone();
    if ncs.is_empty() {
        ncs.push(info.base_dn.clone());
    }
    if !ncs.iter().any(|n| dn::eq(n, &info.base_dn)) {
        ncs.insert(0, info.base_dn.clone());
    }
    for nc in ncs {
        if let Ok(Some(e)) = dir.read(&nc, &["objectClass", "cn", "dc", "ou", "o", "hasSubordinates"]).await {
            roots.push(e);
        } else {
            roots.push(Entry { dn: nc.clone(), attrs: vec![] });
        }
    }
    let target = if q.dn.is_empty() { info.base_dn.clone() } else { q.dn.clone() };
    let tree = tree_to(&mut dir, roots, &target, "(objectClass=*)", TreeMode::Browse).await?;
    let detail = super::objects::browse_detail(&a, &mut dir, &target)
        .await
        .unwrap_or_else(|e| format!("<div class=\"notice danger\">{}</div>", crate::web::html::esc(&e.message)));
    render(&BrowsePage { ctx: a.ctx("browse"), tree, detail })
}
