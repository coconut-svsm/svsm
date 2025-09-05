#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VsockError {
    /// Error when connect operation fails
    ConnectFailed,
    /// Error when send operation fails
    SendFailed,
    /// Error when recv operation fails
    RecvFailed,
    /// Generic error for socket operations on a vsock device.
    Failed,
}
