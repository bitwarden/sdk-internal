pub trait Link {
    fn send(&self, data: Vec<u8>);
    fn receive(&self) -> Vec<u8>;
    fn available_destinations(&self) -> Vec<Destination>;
}
