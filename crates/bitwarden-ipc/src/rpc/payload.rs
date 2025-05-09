pub trait RpcRequest {
    type Response;

    /// Used to identify handlers
    fn name() -> String;
}
