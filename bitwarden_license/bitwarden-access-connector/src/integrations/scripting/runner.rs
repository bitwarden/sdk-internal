//! Process execution behind a trait, so the driver can be tested without spawning anything.

use std::time::Duration;

use async_trait::async_trait;
use tokio::{process::Command, time};

use super::command::CommandSpec;

/// Internal errors from script invocation, translated by `classify_outcome`.
#[derive(Debug, thiserror::Error)]
pub(crate) enum InvokeError {
    /// The stdin payload could not be serialized.
    #[error("payload serialization failed")]
    Serialize(#[source] serde_json::Error),
    /// The process could not be started.
    #[error("script spawn failed")]
    Spawn(#[source] std::io::Error),
    /// Writing the payload to the process's stdin failed.
    #[error("script stdin write failed")]
    StdinWrite(#[source] std::io::Error),
    /// Waiting for the process to exit failed.
    #[error("script wait failed")]
    Wait(#[source] std::io::Error),
    /// The process outlived its timeout and was killed.
    #[error("script timed out")]
    Timeout,
}

/// How a script process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScriptExit {
    /// The process exited with this code.
    Code(i32),
    /// A signal ended the process, with its number when the platform reports one.
    Signal(Option<i32>),
}

impl From<std::process::ExitStatus> for ScriptExit {
    fn from(status: std::process::ExitStatus) -> Self {
        if let Some(code) = status.code() {
            return Self::Code(code);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt as _;
            Self::Signal(status.signal())
        }
        #[cfg(not(unix))]
        Self::Signal(None)
    }
}

/// Runs a [`CommandSpec`] and reports how it exited.
#[async_trait]
pub(crate) trait ScriptRunner: Send + Sync {
    /// Runs `spec` with `payload` on stdin and returns how it exited.
    async fn run(
        &self,
        spec: CommandSpec,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<ScriptExit, InvokeError>;
}

/// Runs scripts as real child processes.
pub(crate) struct ProcessScriptRunner;

#[async_trait]
impl ScriptRunner for ProcessScriptRunner {
    async fn run(
        &self,
        spec: CommandSpec,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<ScriptExit, InvokeError> {
        use tokio::io::AsyncWriteExt as _;

        let mut command = Command::new(&spec.program);
        command
            .args(&spec.args)
            .env_clear()
            .envs(spec.env.iter().map(|(k, v)| (k, v)));

        let mut child = command
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(InvokeError::Spawn)?;

        let run = async {
            if let Some(mut stdin) = child.stdin.take() {
                stdin
                    .write_all(payload)
                    .await
                    .map_err(InvokeError::StdinWrite)?;
            }
            child.wait().await.map_err(InvokeError::Wait)
        };

        match time::timeout(timeout, run).await {
            Ok(Ok(status)) => Ok(status.into()),
            Ok(Err(e)) => Err(e),
            Err(_timeout) => {
                let _ = child.kill().await;
                Err(InvokeError::Timeout)
            }
        }
    }
}

/// A [`ScriptRunner`] that records what it was asked to run and returns a canned outcome.
#[cfg(test)]
pub(crate) struct RecordingRunner {
    reply: Result<ScriptExit, fn() -> InvokeError>,
    calls: std::sync::Mutex<Vec<(CommandSpec, Vec<u8>)>>,
}

#[cfg(test)]
impl RecordingRunner {
    /// A runner whose every invocation exits with `code`.
    pub(crate) fn exiting(code: i32) -> Self {
        Self {
            reply: Ok(ScriptExit::Code(code)),
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// A runner whose every invocation fails with a fresh error from `make`.
    pub(crate) fn failing(make: fn() -> InvokeError) -> Self {
        Self {
            reply: Err(make),
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// The single recorded invocation; panics unless there was exactly one.
    pub(crate) fn only_call(&self) -> (CommandSpec, Vec<u8>) {
        let calls = self.calls.lock().expect("recorder lock");
        assert_eq!(calls.len(), 1, "expected exactly one invocation");
        calls[0].clone()
    }

    /// The stdin payload of the single recorded invocation, parsed as JSON.
    pub(crate) fn only_payload(&self) -> serde_json::Value {
        let (_, payload) = self.only_call();
        serde_json::from_slice(&payload).expect("payload must be JSON")
    }
}

#[cfg(test)]
#[async_trait]
impl ScriptRunner for RecordingRunner {
    async fn run(
        &self,
        spec: CommandSpec,
        payload: &[u8],
        _timeout: Duration,
    ) -> Result<ScriptExit, InvokeError> {
        self.calls
            .lock()
            .expect("recorder lock")
            .push((spec, payload.to_vec()));
        match self.reply {
            Ok(exit) => Ok(exit),
            Err(make) => Err(make()),
        }
    }
}
