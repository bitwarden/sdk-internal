// use crate::link::Link;

// pub struct Proxy<L>
// where
//     L: Link,
// {
//     links: (L, L),
// }

// impl<L> Proxy<L>
// where
//     L: Link,
// {
//     pub fn new(links: (L, L)) -> Self {
//         Self { links }
//     }

//     pub async fn start(&self) {
//         let data = self.links.0.receive().await;
//         self.links.1.send(&data);
//     }
// }
