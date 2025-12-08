use std::collections::BTreeMap;

use tracing_core::{
    Callsite, Field, Interest, Kind, Level, Metadata, callsite::DefaultCallsite, field::FieldSet,
};

pub trait Builder {
    fn create_enabled(
        metadata: &'static Metadata<'static>,
        fields: &'static BTreeMap<&'static str, Field>,
    ) -> Self;
    fn create_disabled(metadata: &'static Metadata<'static>) -> Self;
}
pub struct Factory<T> {
    phantom: std::marker::PhantomData<T>,
    callsite: &'static LateCallsite,
    fields: &'static BTreeMap<&'static str, Field>,
}

impl<T> Factory<T>
where
    T: Builder,
{
    pub fn new(
        name: &str,
        target: &str,
        level: Level,
        file: Option<&str>,
        line: Option<u32>,
        module_path: Option<&str>,
        fields: &[&str],
    ) -> Self {
        // tracing expects everything to be static, so we need to leak everything
        let name = name.to_string().leak();
        let target = target.to_string().leak();
        let file = file.map(|s| s.to_string().leak() as &'static str);
        let module_path = module_path.map(|s| s.to_string().leak() as &'static str);

        let callsite: &'static mut LateCallsite = Box::leak(Box::default());
        let fields = Box::leak(Box::new(
            fields
                .iter()
                .map(|k| k.to_string().leak() as &'static str)
                .collect::<Vec<&'static str>>(),
        ));
        let metadata = Box::leak(Box::new(Metadata::new(
            name,
            target,
            level,
            file,
            line,
            module_path,
            FieldSet::new(fields, tracing_core::identify_callsite!(callsite)),
            Kind::SPAN,
        )));

        callsite
            .delegate
            .set(DefaultCallsite::new(metadata))
            .expect("cannot initialize callsite");

        let fields = Box::leak(Box::new(
            metadata.fields().iter().map(|f| (f.name(), f)).collect(),
        ));
        Factory {
            callsite,
            fields,
            phantom: Default::default(),
        }
    }

    pub fn create(&self) -> T {
        let enabled = ::tracing::Level::INFO <= ::tracing::level_filters::STATIC_MAX_LEVEL
            && *self.callsite.metadata().level()
                <= ::tracing::level_filters::LevelFilter::current()
            && {
                let interest = self.callsite.interest();
                !interest.is_never()
                    && ::tracing::__macro_support::__is_enabled(self.callsite.metadata(), interest)
            };
        if enabled {
            T::create_enabled(self.callsite.metadata(), self.fields)
        } else {
            T::create_disabled(self.callsite.metadata())
        }
    }
}

#[derive(Default)]
struct LateCallsite {
    delegate: std::sync::OnceLock<DefaultCallsite>,
}

impl Callsite for LateCallsite {
    fn set_interest(&self, interest: Interest) {
        self.delegate
            .get()
            .expect("original code used unwrap, should not fail")
            .set_interest(interest);
    }

    fn metadata(&self) -> &Metadata<'_> {
        self.delegate
            .get()
            .expect("original code used unwrap, should not fail")
            .metadata()
    }
}

impl LateCallsite {
    #[inline]
    fn interest(&'static self) -> Interest {
        self.delegate
            .get()
            .expect("cannot get delegate callsite, this is a bug")
            .interest()
    }
}
