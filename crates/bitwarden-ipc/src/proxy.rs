use crate::link::Link;

pub struct Proxy {
    links: (Box<dyn Link>, Box<dyn Link>),
}

impl Proxy {
    pub fn new(links: (Box<dyn Link>, Box<dyn Link>)) -> Self {
        Self { links }
    }

    pub fn start(&self) {
        let data = self.links.0.receive();
        self.links.1.send(&data);
    }
}
