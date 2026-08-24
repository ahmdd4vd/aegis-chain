use thiserror::Error;

#[derive(Debug, Error)]
pub enum AegisError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("runtime error: {0}")]
    Runtime(String),
}

pub type AegisResult<T> = Result<T, AegisError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_error_displays_message() {
        let error = AegisError::Config("invalid yaml".to_string());
        assert_eq!(error.to_string(), "configuration error: invalid yaml");
    }

    #[test]
    fn runtime_error_displays_message() {
        let error = AegisError::Runtime("cargo failed".to_string());
        assert_eq!(error.to_string(), "runtime error: cargo failed");
    }
}
