pub trait RpcPayload {
    type Response;

    /// Used to identify handlers
    fn name() -> String;
}
