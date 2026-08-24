use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GitHubError {
    #[error("github http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("github api returned {status}: {body}")]
    Api { status: u16, body: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueComment {
    pub id: u64,
    pub body: String,
}

pub struct GitHubClient {
    http: reqwest::blocking::Client,
    token: String,
    repo: String,
    base_url: String,
}

impl GitHubClient {
    pub fn new(token: impl Into<String>, repo: impl Into<String>) -> Self {
        Self {
            http: reqwest::blocking::Client::new(),
            token: token.into(),
            repo: repo.into(),
            base_url: "https://api.github.com".to_string(),
        }
    }

    pub fn with_base_url(
        token: impl Into<String>,
        repo: impl Into<String>,
        base_url: impl Into<String>,
    ) -> Self {
        Self {
            http: reqwest::blocking::Client::new(),
            token: token.into(),
            repo: repo.into(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
        }
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::blocking::RequestBuilder {
        let url = format!("{}{}", self.base_url, path);
        self.http
            .request(method, url)
            .bearer_auth(&self.token)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "aegis-chain")
            .header("X-GitHub-Api-Version", "2022-11-28")
    }

    pub fn list_issue_comments(&self, pr_number: u64) -> Result<Vec<IssueComment>, GitHubError> {
        let path = format!("/repos/{}/issues/{pr_number}/comments", self.repo);
        let response = self.request(reqwest::Method::GET, &path).send()?;

        let status = response.status();
        if !status.is_success() {
            return Err(GitHubError::Api {
                status: status.as_u16(),
                body: response.text().unwrap_or_default(),
            });
        }

        response.json::<Vec<IssueComment>>().map_err(Into::into)
    }

    pub fn create_issue_comment(
        &self,
        pr_number: u64,
        body: &str,
    ) -> Result<IssueComment, GitHubError> {
        let path = format!("/repos/{}/issues/{pr_number}/comments", self.repo);
        let payload = serde_json::json!({ "body": body });

        let response = self
            .request(reqwest::Method::POST, &path)
            .json(&payload)
            .send()?;
        let status = response.status();

        if !status.is_success() {
            return Err(GitHubError::Api {
                status: status.as_u16(),
                body: response.text().unwrap_or_default(),
            });
        }

        response.json::<IssueComment>().map_err(Into::into)
    }

    pub fn update_issue_comment(
        &self,
        comment_id: u64,
        body: &str,
    ) -> Result<IssueComment, GitHubError> {
        let path = format!("/repos/{}/issues/comments/{comment_id}", self.repo);
        let payload = serde_json::json!({ "body": body });

        let response = self
            .request(reqwest::Method::PATCH, &path)
            .json(&payload)
            .send()?;
        let status = response.status();

        if !status.is_success() {
            return Err(GitHubError::Api {
                status: status.as_u16(),
                body: response.text().unwrap_or_default(),
            });
        }

        response.json::<IssueComment>().map_err(Into::into)
    }
}
