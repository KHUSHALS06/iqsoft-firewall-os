use crate::{
    app_state::AppState,
    models::address::{AddressGroup, AddressObject},
    services::address_service::AddressService,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::{json, Value};

/// 404 when the service says the thing does not exist, otherwise 400.
fn failure(message: String) -> (StatusCode, Json<Value>) {
    let status = if message.ends_with("not found") {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::BAD_REQUEST
    };

    (status, Json(json!({ "error": message })))
}

fn ok() -> (StatusCode, Json<Value>) {
    (StatusCode::OK, Json(json!({ "status": "ok" })))
}

fn created(id: i64) -> (StatusCode, Json<Value>) {
    (StatusCode::OK, Json(json!({ "status": "ok", "id": id })))
}

// ----------------------------------------------------------------------
// Address objects
// ----------------------------------------------------------------------

pub async fn list_objects(State(state): State<AppState>) -> impl IntoResponse {
    match AddressService::list_objects(&state.db).await {
        Ok(objects) => (StatusCode::OK, Json(json!(objects))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
    }
}

pub async fn add_object(
    State(state): State<AppState>,
    Json(object): Json<AddressObject>,
) -> impl IntoResponse {
    match AddressService::add_object(&state.db, object).await {
        Ok(id) => created(id),
        Err(e) => failure(e),
    }
}

pub async fn update_object(
    Path(id): Path<i64>,
    State(state): State<AppState>,
    Json(object): Json<AddressObject>,
) -> impl IntoResponse {
    match AddressService::update_object(&state.db, id, object).await {
        Ok(_) => ok(),
        Err(e) => failure(e),
    }
}

pub async fn delete_object(
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match AddressService::delete_object(&state.db, id).await {
        Ok(_) => ok(),
        Err(e) => failure(e),
    }
}

// ----------------------------------------------------------------------
// Address groups
// ----------------------------------------------------------------------

pub async fn list_groups(State(state): State<AppState>) -> impl IntoResponse {
    match AddressService::list_groups(&state.db).await {
        Ok(groups) => (StatusCode::OK, Json(json!(groups))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
    }
}

pub async fn add_group(
    State(state): State<AppState>,
    Json(group): Json<AddressGroup>,
) -> impl IntoResponse {
    match AddressService::add_group(&state.db, group).await {
        Ok(id) => created(id),
        Err(e) => failure(e),
    }
}

pub async fn update_group(
    Path(id): Path<i64>,
    State(state): State<AppState>,
    Json(group): Json<AddressGroup>,
) -> impl IntoResponse {
    match AddressService::update_group(&state.db, id, group).await {
        Ok(_) => ok(),
        Err(e) => failure(e),
    }
}

pub async fn delete_group(
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match AddressService::delete_group(&state.db, id).await {
        Ok(_) => ok(),
        Err(e) => failure(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        database::init::initialize_database,
        firewall::safe_commit::SafeCommit,
        services::login_throttle::LoginThrottle,
    };
    use sqlx::sqlite::SqlitePoolOptions;
    use std::sync::Arc;

    async fn test_state() -> AppState {
        // One connection, otherwise every connection would get its own empty in-memory database.
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        initialize_database(&db).await.unwrap();

        AppState {
            db,
            commit_lock: Arc::new(tokio::sync::Mutex::new(())),
            login_throttle: LoginThrottle::new(),
            safe_commit: SafeCommit::new(),
        }
    }

    async fn read(response: impl IntoResponse) -> (StatusCode, Value) {
        let response = response.into_response();
        let status = response.status();

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();

        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);

        (status, body)
    }

    fn object(name: &str, value: &str) -> AddressObject {
        AddressObject {
            id: None,
            name: name.into(),
            kind: "host".into(),
            value: value.into(),
            family: String::new(),
            comment: None,
        }
    }

    fn group(name: &str, members: &[&str]) -> AddressGroup {
        AddressGroup {
            id: None,
            name: name.into(),
            family: String::new(),
            comment: None,
            members: members.iter().map(|m| m.to_string()).collect(),
        }
    }

    #[tokio::test]
    async fn add_and_list_objects() {
        let state = test_state().await;

        let (status, body) =
            read(add_object(State(state.clone()), Json(object("web1", "10.0.0.1"))).await).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ok");
        assert!(body["id"].as_i64().unwrap() > 0);

        let (status, body) = read(list_objects(State(state.clone())).await).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_array().unwrap().len(), 1);
        assert_eq!(body[0]["name"], "web1");
        assert_eq!(body[0]["family"], "ipv4");
    }

    #[tokio::test]
    async fn invalid_input_is_400_with_a_message() {
        let state = test_state().await;

        let (status, body) =
            read(add_object(State(state.clone()), Json(object("bad name", "10.0.0.1"))).await).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"].as_str().unwrap().contains("Name"));

        let (status, body) =
            read(add_object(State(state.clone()), Json(object("ok", "10.0.0.999"))).await).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"].as_str().unwrap().contains("not a valid"));

        let (status, body) = read(list_objects(State(state.clone())).await).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn missing_ids_are_404() {
        let state = test_state().await;

        let (status, _) = read(
            update_object(Path(999), State(state.clone()), Json(object("x", "10.0.0.1"))).await,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _) = read(delete_object(Path(999), State(state.clone())).await).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _) = read(
            update_group(Path(999), State(state.clone()), Json(group("x", &[]))).await,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _) = read(delete_group(Path(999), State(state.clone())).await).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn object_update_and_delete() {
        let state = test_state().await;

        let (_, body) =
            read(add_object(State(state.clone()), Json(object("web1", "10.0.0.1"))).await).await;
        let id = body["id"].as_i64().unwrap();

        let (status, body) = read(
            update_object(Path(id), State(state.clone()), Json(object("web1", "10.0.0.9"))).await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ok");

        let (_, body) = read(list_objects(State(state.clone())).await).await;
        assert_eq!(body[0]["value"], "10.0.0.9");

        let (status, _) = read(delete_object(Path(id), State(state.clone())).await).await;
        assert_eq!(status, StatusCode::OK);

        let (_, body) = read(list_objects(State(state.clone())).await).await;
        assert!(body.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn groups_and_delete_protection() {
        let state = test_state().await;

        let (_, body) =
            read(add_object(State(state.clone()), Json(object("web1", "10.0.0.1"))).await).await;
        let object_id = body["id"].as_i64().unwrap();

        let (status, body) = read(
            add_group(State(state.clone()), Json(group("servers", &["web1"]))).await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let group_id = body["id"].as_i64().unwrap();

        let (_, body) = read(list_groups(State(state.clone())).await).await;
        assert_eq!(body[0]["name"], "servers");
        assert_eq!(body[0]["family"], "ipv4");
        assert_eq!(body[0]["members"][0], "web1");

        // the object is in a group: 400 and the message names the group
        let (status, body) = read(delete_object(Path(object_id), State(state.clone())).await).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"].as_str().unwrap().contains("servers"));

        // remove the group first, then the object can go
        let (status, _) = read(delete_group(Path(group_id), State(state.clone())).await).await;
        assert_eq!(status, StatusCode::OK);

        let (status, _) = read(delete_object(Path(object_id), State(state.clone())).await).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn group_with_unknown_member_is_400() {
        let state = test_state().await;

        let (status, body) = read(
            add_group(State(state.clone()), Json(group("servers", &["ghost"]))).await,
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"].as_str().unwrap().contains("Unknown address object"));
    }

    #[tokio::test]
    async fn client_supplied_family_is_ignored() {
        let state = test_state().await;

        let json_body = r#"{"name":"v6","kind":"host","value":"2001:db8::1","family":"ipv4"}"#;
        let parsed: AddressObject = serde_json::from_str(json_body).unwrap();

        let (status, _) = read(add_object(State(state.clone()), Json(parsed)).await).await;
        assert_eq!(status, StatusCode::OK);

        let (_, body) = read(list_objects(State(state.clone())).await).await;
        assert_eq!(body[0]["family"], "ipv6");
    }

    #[test]
    fn json_without_optional_fields_parses() {
        let object: AddressObject =
            serde_json::from_str(r#"{"name":"a","kind":"host","value":"10.0.0.1"}"#).unwrap();
        assert!(object.id.is_none() && object.comment.is_none());

        let group: AddressGroup = serde_json::from_str(r#"{"name":"g"}"#).unwrap();
        assert!(group.members.is_empty());
    }
}
