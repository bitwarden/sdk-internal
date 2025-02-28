use std::rc::Rc;

use bitwarden_core::Client;
use js_sys::Promise;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct TestClient(Rc<Client>);

impl TestClient {
    pub fn new(client: Rc<Client>) -> Self {
        Self(client)
    }
}

#[wasm_bindgen]
pub struct TestSub1Client(Rc<Client>);

#[wasm_bindgen]
pub struct TestSub2Client(Rc<Client>);

#[allow(clippy::unused_async)]
#[wasm_bindgen]
impl TestClient {
    pub fn sub1(&self) -> TestSub1Client {
        TestSub1Client(self.0.clone())
    }

    #[allow(clippy::unused_async)]
    pub async fn async_echo(&self, msg: String) -> String {
        format!("ECHOED: '{}'", msg.to_uppercase())
    }
}

#[allow(clippy::unused_async)]
#[wasm_bindgen]
impl TestSub1Client {
    pub fn sub2(&self) -> TestSub2Client {
        TestSub2Client(self.0.clone())
    }

    pub async fn async_echo_cb(
        &self,
        #[wasm_bindgen(unchecked_param_type = "(text: string) => Promise<string>")]
        f: &js_sys::Function,
    ) -> Result<String, JsValue> {
        let this = JsValue::null();
        let val = f.call1(&this, &"hello".into())?;

        let pr: Promise = val.dyn_into()?;
        let fut = wasm_bindgen_futures::JsFuture::from(pr);
        let val = fut
            .await?
            .as_string()
            .ok_or_else(|| js_sys::Error::new("result is not a string"))?;

        Ok(format!("Result async: '{}'", val.to_uppercase()))
    }
}

#[allow(clippy::unused_async)]
#[wasm_bindgen]
impl TestSub2Client {
    #[allow(clippy::unused_async)]
    pub async fn get_flags(&self) -> String {
        format!("{:?}", self.0.internal.get_flags())
    }
}
