use crate::client::{GitHubClient, GitHubError};

pub const REPORT_MARKER: &str = "<!-- aegis-chain:report:v1 -->";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpsertOutcome {
    Created { comment_id: u64 },
    Updated { comment_id: u64 },
}

pub fn upsert_report_comment(
    client: &GitHubClient,
    pr_number: u64,
    markdown: &str,
) -> Result<UpsertOutcome, GitHubError> {
    if !markdown.contains(REPORT_MARKER) {
        return Err(GitHubError::Api {
            status: 0,
            body: "report body is missing the aegis-chain marker; refusing to post".to_string(),
        });
    }

    let comments = client.list_issue_comments(pr_number)?;

    match comments
        .iter()
        .rev()
        .find(|comment| comment.body.contains(REPORT_MARKER))
    {
        Some(existing) => {
            client.update_issue_comment(existing.id, markdown)?;
            Ok(UpsertOutcome::Updated {
                comment_id: existing.id,
            })
        }
        None => {
            let created = client.create_issue_comment(pr_number, markdown)?;
            Ok(UpsertOutcome::Created {
                comment_id: created.id,
            })
        }
    }
}
