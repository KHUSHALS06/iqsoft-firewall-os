use crate::{
    app_state::AppState,
    models::{
        auth::User,
        role::{CreateUserRequest, RoleRequest, UpdateUserRequest},
    },
    services::{
        audit_service::{actions, AuditEvent, AuditService},
        permissions,
        role_service::{AccessError, RoleService},
        user_service::UserService,
    },
};
use axum::{
    extract::{ConnectInfo, Path, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde_json::{json, Value};
use std::net::SocketAddr;

type Reply = (StatusCode, Json<Value>);

fn reply(status: StatusCode, message: &str) -> Reply {
    (status, Json(json!({ "error": message })))
}

fn denied(message: &str) -> Reply {
    reply(StatusCode::FORBIDDEN, message)
}

fn error_reply(e: &AccessError) -> Reply {
    match e {
        AccessError::BadRequest(m) => reply(StatusCode::BAD_REQUEST, m),
        AccessError::Forbidden(m) => reply(StatusCode::FORBIDDEN, m),
        AccessError::NotFound(m) => reply(StatusCode::NOT_FOUND, m),
        AccessError::Conflict(m) => reply(StatusCode::CONFLICT, m),
        AccessError::Internal(m) => {
            eprintln!("access internal error: {}", m);
            reply(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        }
    }
}

/// The reason written to the audit trail: the fixed text of the refusal, or a generic
/// note for internal errors. Nothing the client sent is ever copied into it.
fn reason(e: &AccessError) -> &str {
    match e {
        AccessError::BadRequest(m)
        | AccessError::Forbidden(m)
        | AccessError::NotFound(m)
        | AccessError::Conflict(m) => m,
        AccessError::Internal(_) => "internal error",
    }
}

fn check(user: &User, wanted: &[&str]) -> Result<(), Reply> {
    if wanted.iter().any(|p| user.can(p)) {
        Ok(())
    } else {
        Err(denied("Your role does not allow this action"))
    }
}

/// GET /api/permissions
/// The list of features and what can be allowed on each, for the role editor.
pub async fn catalog(Extension(user): Extension<User>) -> Reply {
    if let Err(r) = check(&user, &["roles.view", "roles.create", "roles.edit"]) {
        return r;
    }

    let features: Vec<Value> = permissions::FEATURES
        .iter()
        .map(|(id, label, actions)| json!({ "id": id, "label": label, "actions": actions }))
        .collect();

    (StatusCode::OK, Json(json!({ "features": features })))
}

/* ---------------- users ---------------- */

/// GET /api/users
pub async fn list_users(State(state): State<AppState>, Extension(user): Extension<User>) -> Reply {
    if let Err(r) = check(&user, &["users.view"]) {
        return r;
    }

    match UserService::list(&state.db).await {
        Ok(users) => (StatusCode::OK, Json(json!(users))),
        Err(e) => error_reply(&e),
    }
}

/// POST /api/users
pub async fn create_user(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(user): Extension<User>,
    Json(req): Json<CreateUserRequest>,
) -> Reply {
    if let Err(r) = check(&user, &["users.create"]) {
        return r;
    }

    let name = req.username.trim().to_string();

    match UserService::create(&state.db, &user, req).await {
        Ok(created) => {
            AuditService::record(
                &state.db,
                AuditEvent::new(actions::USER_CREATE)
                    .user(&user)
                    .source_ip(addr.ip())
                    .target(&format!("user:{}", created.username))
                    .detail(&format!("role {}", created.role)),
            )
            .await;

            (StatusCode::CREATED, Json(json!(created)))
        }
        Err(e) => {
            AuditService::record(
                &state.db,
                AuditEvent::new(actions::USER_CREATE)
                    .user(&user)
                    .source_ip(addr.ip())
                    .target(&format!("user:{}", name))
                    .detail(reason(&e))
                    .failed(),
            )
            .await;

            error_reply(&e)
        }
    }
}

/// PUT /api/users/{id}
pub async fn update_user(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(user): Extension<User>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateUserRequest>,
) -> Reply {
    if let Err(r) = check(&user, &["users.edit"]) {
        return r;
    }

    let mut changes = Vec::new();
    if req.role_id.is_some() {
        changes.push("role");
    }
    if req.enabled.is_some() {
        changes.push("status");
    }
    if req.password.as_deref().map_or(false, |p| !p.is_empty()) {
        changes.push("password reset");
    }
    let detail = if changes.is_empty() {
        "no changes".to_string()
    } else {
        changes.join(", ")
    };

    match UserService::update(&state.db, &user, id, req).await {
        Ok(updated) => {
            AuditService::record(
                &state.db,
                AuditEvent::new(actions::USER_UPDATE)
                    .user(&user)
                    .source_ip(addr.ip())
                    .target(&format!("user:{}", updated.username))
                    .detail(&format!("{} (role {})", detail, updated.role)),
            )
            .await;

            (StatusCode::OK, Json(json!(updated)))
        }
        Err(e) => {
            AuditService::record(
                &state.db,
                AuditEvent::new(actions::USER_UPDATE)
                    .user(&user)
                    .source_ip(addr.ip())
                    .target(&format!("user:{}", id))
                    .detail(reason(&e))
                    .failed(),
            )
            .await;

            error_reply(&e)
        }
    }
}

/// DELETE /api/users/{id}
pub async fn delete_user(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(user): Extension<User>,
    Path(id): Path<i64>,
) -> Reply {
    if let Err(r) = check(&user, &["users.delete"]) {
        return r;
    }

    match UserService::delete(&state.db, &user, id).await {
        Ok(removed) => {
            AuditService::record(
                &state.db,
                AuditEvent::new(actions::USER_DELETE)
                    .user(&user)
                    .source_ip(addr.ip())
                    .target(&format!("user:{}", removed.username))
                    .detail(&format!("role {}", removed.role)),
            )
            .await;

            (StatusCode::OK, Json(json!({ "status": "ok" })))
        }
        Err(e) => {
            AuditService::record(
                &state.db,
                AuditEvent::new(actions::USER_DELETE)
                    .user(&user)
                    .source_ip(addr.ip())
                    .target(&format!("user:{}", id))
                    .detail(reason(&e))
                    .failed(),
            )
            .await;

            error_reply(&e)
        }
    }
}

/* ---------------- roles ---------------- */

/// GET /api/roles
/// People who manage users need the list too, to pick a role from.
pub async fn list_roles(State(state): State<AppState>, Extension(user): Extension<User>) -> Reply {
    if let Err(r) = check(
        &user,
        &["roles.view", "users.view", "users.create", "users.edit"],
    ) {
        return r;
    }

    match RoleService::list(&state.db).await {
        Ok(roles) => (StatusCode::OK, Json(json!(roles))),
        Err(e) => error_reply(&e),
    }
}

/// POST /api/roles
pub async fn create_role(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(user): Extension<User>,
    Json(req): Json<RoleRequest>,
) -> Reply {
    if let Err(r) = check(&user, &["roles.create"]) {
        return r;
    }

    let name = req.name.trim().to_string();

    match RoleService::create(&state.db, &user, req).await {
        Ok(role) => {
            AuditService::record(
                &state.db,
                AuditEvent::new(actions::ROLE_CREATE)
                    .user(&user)
                    .source_ip(addr.ip())
                    .target(&format!("role:{}", role.name))
                    .detail(&format!("{} permissions", role.permissions.len())),
            )
            .await;

            (StatusCode::CREATED, Json(json!(role)))
        }
        Err(e) => {
            AuditService::record(
                &state.db,
                AuditEvent::new(actions::ROLE_CREATE)
                    .user(&user)
                    .source_ip(addr.ip())
                    .target(&format!("role:{}", name))
                    .detail(reason(&e))
                    .failed(),
            )
            .await;

            error_reply(&e)
        }
    }
}

/// PUT /api/roles/{id}
pub async fn update_role(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(user): Extension<User>,
    Path(id): Path<i64>,
    Json(req): Json<RoleRequest>,
) -> Reply {
    if let Err(r) = check(&user, &["roles.edit"]) {
        return r;
    }

    match RoleService::update(&state.db, &user, id, req).await {
        Ok(role) => {
            AuditService::record(
                &state.db,
                AuditEvent::new(actions::ROLE_UPDATE)
                    .user(&user)
                    .source_ip(addr.ip())
                    .target(&format!("role:{}", role.name))
                    .detail(&format!("{} permissions", role.permissions.len())),
            )
            .await;

            (StatusCode::OK, Json(json!(role)))
        }
        Err(e) => {
            AuditService::record(
                &state.db,
                AuditEvent::new(actions::ROLE_UPDATE)
                    .user(&user)
                    .source_ip(addr.ip())
                    .target(&format!("role:{}", id))
                    .detail(reason(&e))
                    .failed(),
            )
            .await;

            error_reply(&e)
        }
    }
}

/// DELETE /api/roles/{id}
pub async fn delete_role(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(user): Extension<User>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    if let Err(r) = check(&user, &["roles.delete"]) {
        return r;
    }

    match RoleService::delete(&state.db, &user, id).await {
        Ok(role) => {
            AuditService::record(
                &state.db,
                AuditEvent::new(actions::ROLE_DELETE)
                    .user(&user)
                    .source_ip(addr.ip())
                    .target(&format!("role:{}", role.name)),
            )
            .await;

            (StatusCode::OK, Json(json!({ "status": "ok" })))
        }
        Err(e) => {
            AuditService::record(
                &state.db,
                AuditEvent::new(actions::ROLE_DELETE)
                    .user(&user)
                    .source_ip(addr.ip())
                    .target(&format!("role:{}", id))
                    .detail(reason(&e))
                    .failed(),
            )
            .await;

            error_reply(&e)
        }
    }
}
