use bitwarden_core::Client;

use crate::link::Link;

pub struct IpcClient<'a> {
    #[allow(dead_code)]
    pub(crate) client: &'a Client,
}

impl<'a> IpcClient<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self { client }
    }

    // pub fn create_manager<L: Link>(&self, link: L) {
    //     todo!()
    // }
}

pub trait IpcClientExt<'a> {
    fn ipc(&'a self) -> IpcClient<'a>;
}

impl<'a> IpcClientExt<'a> for Client {
    fn ipc(&'a self) -> IpcClient<'a> {
        IpcClient::new(self)
    }
}
