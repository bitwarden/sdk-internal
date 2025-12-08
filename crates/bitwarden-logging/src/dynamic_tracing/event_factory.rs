use std::collections::BTreeMap;

use tracing::{
    Metadata,
    field::{Field, Value},
};

use super::factory::{Builder, Factory};

/// Event factory allows creating events with attributes defined at runtime.
/// It leaks memory to do this, so create event factories once and reuse them.
pub type EventFactory<'a> = Factory<EventBuilder<'a>>;

pub enum EventBuilder<'a> {
    Enabled {
        metadata: &'static Metadata<'static>,
        fields: &'static BTreeMap<&'static str, Field>,
        values: Vec<(&'static Field, Option<&'a dyn Value>)>,
        parent: Option<tracing::Id>,
    },
    Disabled,
}

impl Builder for EventBuilder<'_> {
    fn create_enabled(
        metadata: &'static Metadata<'static>,
        fields: &'static BTreeMap<&'static str, Field>,
    ) -> Self {
        EventBuilder::Enabled {
            metadata,
            fields,
            values: Vec::new(),
            parent: None,
        }
    }
    fn create_disabled(_metadata: &'static Metadata<'static>) -> Self {
        EventBuilder::Disabled
    }
}

impl<'a> EventBuilder<'a> {
    #[inline]
    pub fn with(&mut self, name: &str, value: &'a dyn Value) -> &mut Self {
        if let EventBuilder::Enabled { values, fields, .. } = self {
            if let Some(field) = fields.get(name) {
                values.push((field, Some(value)));
            }
        }
        self
    }

    pub fn with_span_id(&mut self, parent: Option<tracing::Id>) -> &mut Self {
        if let EventBuilder::Enabled { parent: p, .. } = self {
            *p = parent;
        }
        self
    }

    #[inline]
    pub fn build(&self) {
        if let EventBuilder::Enabled {
            parent,
            metadata,
            values,
            ..
        } = self
        {
            macro_rules! finish {
                ($n:literal) => {
                    if $n == values.len() {
                        let values: [(&'static Field, Option<&'a (dyn Value)>); $n] =
                            values.as_slice().try_into().unwrap();
                        let value_set = metadata.fields().value_set(&values);
                        ::tracing::Event::child_of(parent.clone(), metadata, &value_set);
                        return;
                    }
                };
            }
            if values.len() < 10 {
                finish!(0);
                finish!(1);
                finish!(2);
                finish!(3);
                finish!(4);
                finish!(5);
                finish!(6);
                finish!(7);
                finish!(8);
                finish!(9);
            }
            if values.len() < 20 {
                finish!(10);
                finish!(11);
                finish!(12);
                finish!(13);
                finish!(14);
                finish!(15);
                finish!(16);
                finish!(17);
                finish!(18);
                finish!(19);
            }
            if values.len() < 30 {
                finish!(20);
                finish!(21);
                finish!(22);
                finish!(23);
                finish!(24);
                finish!(25);
                finish!(26);
                finish!(27);
                finish!(28);
                finish!(29);
            }
            if values.len() < 40 {
                finish!(30);
                finish!(31);
                finish!(32);
                finish!(33);
                finish!(34);
                finish!(35);
                finish!(36);
                finish!(37);
                finish!(38);
                finish!(39);
            }
            if values.len() < 50 {
                finish!(40);
                finish!(41);
                finish!(42);
                finish!(43);
                finish!(44);
                finish!(45);
                finish!(46);
                finish!(47);
                finish!(48);
                finish!(49);
            }
            if values.len() < 60 {
                finish!(50);
                finish!(51);
                finish!(52);
                finish!(53);
                finish!(54);
                finish!(55);
                finish!(56);
                finish!(57);
                finish!(58);
                finish!(59);
            }
            if values.len() < 70 {
                finish!(60);
                finish!(61);
                finish!(62);
                finish!(63);
                finish!(64);
                finish!(65);
                finish!(66);
                finish!(67);
                finish!(68);
                finish!(69);
            }
            if values.len() < 80 {
                finish!(70);
                finish!(71);
                finish!(72);
                finish!(73);
                finish!(74);
                finish!(75);
                finish!(76);
                finish!(77);
                finish!(78);
                finish!(79);
            }
            if values.len() < 90 {
                finish!(90);
                finish!(91);
                finish!(92);
                finish!(93);
                finish!(94);
                finish!(95);
                finish!(96);
                finish!(97);
                finish!(98);
                finish!(99);
            }
            if values.len() < 110 {
                finish!(100);
            }
            panic!("too many attributes, up to 100 are supported")
        }
    }
}

// #[cfg(test)]
// mod test {
//     use std::sync::{Arc, Mutex};

//     use tracing_core::Level;

//     use crate::event_factory::EventFactory;

//     #[derive(Clone, Default)]
//     struct TestWriter {
//         buffer: Arc<Mutex<Vec<u8>>>,
//     }

//     impl std::io::Write for TestWriter {
//         fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
//             let buf_len = buf.len();
//             self.buffer.lock().unwrap().append(&mut buf.to_vec());
//             Ok(buf_len)
//         }

//         fn flush(&mut self) -> std::io::Result<()> {
//             Ok(())
//         }
//     }
//     #[test]
//     fn test_unfiltered() {
//         test(Level::INFO)
//     }
//     #[test]
//     fn test_filtered() {
//         test(Level::ERROR)
//     }

//     fn test(subscriber_level: Level) {
//         let test_writer = TestWriter::default();
//         let attrs = vec!["dyn_attr_1", "dyn_attr_2"];
//         let event_factory = EventFactory::new(
//             "event_name",
//             "event_target",
//             Level::INFO,
//             None,
//             None,
//             None,
//             &attrs,
//         );
//         let subscriber = tracing_subscriber::fmt()
//             .json()
//             .without_time()
//             .with_file(false)
//             .with_line_number(false)
//             .with_max_level(subscriber_level)
//             .with_writer(Mutex::new(test_writer.clone()))
//             .finish();

//         tracing::subscriber::with_default(subscriber, || {
//             let mut event = event_factory.create();
//             event.with("dyn_attr_1", &"dyn_attr_1");
//             event.with("dyn_attr_2", &"dyn_attr_2");
//             event.with("dyn_attr_4", &"dyn_attr_4");
//             event.build();
//         });

//         insta::assert_snapshot!(
//             subscriber_level.to_string(),
//             String::from_utf8(test_writer.buffer.lock().unwrap().to_vec()).unwrap()
//         );
//     }
// }
