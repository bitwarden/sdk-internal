use crate::message::Message;

pub trait CommunicationProvider {
    type SendError;
    type ReceiveError;

    fn send(
        &self,
        message: Message,
    ) -> impl std::future::Future<Output = Result<(), Self::SendError>>;
    fn receive(&self) -> impl std::future::Future<Output = Result<Message, Self::ReceiveError>>;
}
