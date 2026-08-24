pub mod client;
pub mod comment;

pub use client::{GitHubClient, GitHubError, IssueComment};
pub use comment::{upsert_report_comment, UpsertOutcome, REPORT_MARKER};
