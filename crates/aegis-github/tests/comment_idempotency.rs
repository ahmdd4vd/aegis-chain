use aegis_github::{upsert_report_comment, GitHubClient, UpsertOutcome, REPORT_MARKER};
use mockito::Server;

fn client_for(server_url: &str) -> GitHubClient {
    GitHubClient::with_base_url("test-token", "acme/widget", server_url)
}

#[test]
fn creates_comment_when_none_exists() {
    let mut server = Server::new();

    let list_mock = server
        .mock("GET", "/repos/acme/widget/issues/7/comments")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body("[]")
        .create();

    let create_mock = server
        .mock("POST", "/repos/acme/widget/issues/7/comments")
        .match_body(mockito::Matcher::Regex(
            "(?s).*aegis-chain:report:v1.*".to_string(),
        ))
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(r#"{"id": 111, "body": "placeholder"}"#)
        .create();

    let markdown = format!("{REPORT_MARKER}\n## Aegis Chain Report\n\nhello");
    let outcome = upsert_report_comment(&client_for(&server.url()), 7, &markdown).unwrap();

    assert_eq!(outcome, UpsertOutcome::Created { comment_id: 111 });
    list_mock.assert();
    create_mock.assert();
}

#[test]
fn updates_existing_marker_comment_instead_of_creating_new_one() {
    let mut server = Server::new();

    let existing = serde_json::json!([
        { "id": 42, "body": "human comment without marker" },
        { "id": 99, "body": format!("stale report\n{REPORT_MARKER}") }
    ])
    .to_string();

    let list_mock = server
        .mock("GET", "/repos/acme/widget/issues/7/comments")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(existing)
        .create();

    let patch_mock = server
        .mock("PATCH", "/repos/acme/widget/issues/comments/99")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"id": 99, "body": "updated"}"#)
        .create();

    let markdown = format!("{REPORT_MARKER}\n## Aegis Chain Report\n\nfresh");
    let outcome = upsert_report_comment(&client_for(&server.url()), 7, &markdown).unwrap();

    assert_eq!(outcome, UpsertOutcome::Updated { comment_id: 99 });
    list_mock.assert();
    patch_mock.assert();
}

#[test]
fn refuses_to_post_body_without_marker() {
    let server = Server::new();
    let outcome = upsert_report_comment(&client_for(&server.url()), 7, "no marker here");

    assert!(outcome.is_err());
}
