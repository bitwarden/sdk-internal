//! [`BwStream`], a stream produced a chunk at a time that JavaScript receives as an
//! `AsyncIterable`.
//!
//! The iterable is a plain object built at runtime, so it needs no JavaScript shipped next to the
//! wasm module.

use std::{cell::RefCell, collections::VecDeque, marker::PhantomData, rc::Rc};

use futures::{Stream, StreamExt, stream::LocalBoxStream};
use wasm_bindgen::{
    JsValue, closure::Closure, convert::IntoWasmAbi, describe::WasmDescribe, prelude::wasm_bindgen,
};
use wasm_bindgen_futures::{
    JsFuture, future_to_promise,
    js_sys::{Object, Promise, Reflect, Symbol},
};

#[wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
/**
 * An item that either succeeded with a `value` or failed with an `error`, as a
 * `BwStream<Result<T, E>>` yields them. Narrow on `ok`.
 */
export type BwResult<T, E> = { ok: true; value: T } | { ok: false; error: E };
"#;

/// Chunks of items already converted to JavaScript values, or the error that ends the stream.
type Chunks = LocalBoxStream<'static, Result<Vec<JsValue>, JsValue>>;

/// A stream of `T`, produced a chunk at a time, that JavaScript receives as an `AsyncIterable`.
///
/// A `#[wasm_export]` method returns `BwStream<T>` and declares the TypeScript type with
/// `#[wasm_bindgen(unchecked_return_type = "AsyncIterable<T>")]`. A stream of `Result<T, E>` items,
/// built with [`BwStream::from_results`], yields `BwResult<T, E>` objects:
/// `{ ok: true, value }` or `{ ok: false, error }`, declared as
/// `"AsyncIterable<BwResult<T, E>>"`. `T` records what JavaScript receives; the items are
/// converted when a chunk arrives.
///
/// Each chunk is converted into JavaScript values when it arrives and handed out one item per
/// `next()`, so WASM memory holds at most one chunk. A `next()` with a converted item waiting
/// resolves without polling the stream. Calls that overlap run one after another, in call order.
///
/// An error from the stream itself rejects that `next()` and ends the iteration; later calls
/// return done. `return()`, which `break` in a `for await` calls, drops the stream and the waiting
/// items. The stream is also dropped once it ends, so only the empty iterator object waits for
/// garbage collection.
pub struct BwStream<T> {
    chunks: Chunks,
    item: PhantomData<fn() -> T>,
}

impl<T: Into<JsValue> + 'static> BwStream<T> {
    /// Wraps a stream of chunks, each item converted with `Into<JsValue>`. An empty chunk is
    /// skipped, not the end of the stream. An `Err` ends the stream.
    pub fn new<F: Into<JsValue>>(chunks: impl Stream<Item = Result<Vec<T>, F>> + 'static) -> Self {
        Self::from_converted(chunks, Into::into)
    }
}

impl<T: Into<JsValue> + 'static, E: Into<JsValue> + 'static> BwStream<Result<T, E>> {
    /// Wraps a stream of chunks of results, each item converted to a `BwResult` object. An empty
    /// chunk is skipped, not the end of the stream. An `Err` chunk ends the stream; an `Err` item
    /// is handed out as `{ ok: false, error }` and the stream goes on.
    pub fn from_results<F: Into<JsValue>>(
        chunks: impl Stream<Item = Result<Vec<Result<T, E>>, F>> + 'static,
    ) -> Self {
        Self::from_converted(chunks, |item| match item {
            Ok(value) => object(&[("ok", &true.into()), ("value", &value.into())]),
            Err(error) => object(&[("ok", &false.into()), ("error", &error.into())]),
        })
    }
}

impl<T> BwStream<T> {
    fn from_converted<I: 'static, F: Into<JsValue>>(
        chunks: impl Stream<Item = Result<Vec<I>, F>> + 'static,
        convert: fn(I) -> JsValue,
    ) -> Self {
        let chunks = chunks
            .map(move |chunk| match chunk {
                Ok(items) => Ok(items.into_iter().map(convert).collect()),
                Err(error) => Err(error.into()),
            })
            .boxed_local();
        Self {
            chunks,
            item: PhantomData,
        }
    }
}

impl<T> From<BwStream<T>> for JsValue {
    fn from(stream: BwStream<T>) -> Self {
        async_iterator(stream.chunks)
    }
}

impl<T> WasmDescribe for BwStream<T> {
    fn describe() {
        JsValue::describe();
    }
}

impl<T> IntoWasmAbi for BwStream<T> {
    type Abi = <JsValue as IntoWasmAbi>::Abi;

    fn into_abi(self) -> Self::Abi {
        JsValue::from(self).into_abi()
    }
}

/// What `next()` and `return()` share. Neither holds a borrow across an `.await`.
struct State {
    /// `None` once the stream ended, failed or was closed, and while a pull has it.
    chunks: Option<Chunks>,
    /// Converted items not yet handed out.
    buffer: VecDeque<JsValue>,
    /// The latest `next()` that had to wait, which the next one waits for in turn.
    tail: Option<Promise>,
    /// `next()` calls that are waiting or pulling.
    queued: u32,
    /// Set by `return()`, so a pull still in flight drops what it receives.
    closed: bool,
}

/// Builds `{ next, return, [Symbol.asyncIterator] }` over `chunks`.
///
/// The closures go to the JavaScript garbage collector, which frees their Rust side when the
/// functions are collected. They capture only [`State`], never the iterator object: a Rust
/// reference to the object would keep it, and so the closures, alive forever.
fn async_iterator(chunks: Chunks) -> JsValue {
    let state = Rc::new(RefCell::new(State {
        chunks: Some(chunks),
        buffer: VecDeque::new(),
        tail: None,
        queued: 0,
        closed: false,
    }));
    let iterator = Object::new();

    let next = {
        let state = state.clone();
        Closure::<dyn FnMut() -> Promise>::new(move || next(&state)).into_js_value()
    };
    let close = Closure::<dyn FnMut(JsValue) -> Promise>::new(move |value| close(&state, value))
        .into_js_value();
    // `[Symbol.asyncIterator]()` returns the iterator itself. `Object.prototype.valueOf` returns
    // its `this`, which a closure cannot see without capturing the object.
    let value_of = get(&iterator, &"valueOf".into());

    set(&iterator, &"next".into(), &next);
    set(&iterator, &"return".into(), &close);
    set(&iterator, &Symbol::async_iterator(), &value_of);
    iterator.into()
}

fn next(state: &Rc<RefCell<State>>) -> Promise {
    let mut current = state.borrow_mut();
    if current.queued == 0 {
        if let Some(item) = current.buffer.pop_front() {
            return Promise::resolve(&result(&item, false));
        }
        if current.chunks.is_none() {
            return Promise::resolve(&result(&JsValue::UNDEFINED, true));
        }
    }

    let previous = current.tail.take();
    current.queued += 1;
    drop(current);

    let pulling = state.clone();
    let promise = future_to_promise(async move {
        if let Some(previous) = previous {
            // Only the order matters here; the previous call reports its own failure.
            let _ = JsFuture::from(previous).await;
        }
        let result = pull(&pulling).await;
        let mut current = pulling.borrow_mut();
        current.queued -= 1;
        if current.queued == 0 {
            current.tail = None;
        }
        result
    });
    state.borrow_mut().tail = Some(promise.clone());
    promise
}

/// Hands out the next item, polling the stream for a chunk while none is waiting.
async fn pull(state: &Rc<RefCell<State>>) -> Result<JsValue, JsValue> {
    loop {
        let mut chunks = {
            let mut current = state.borrow_mut();
            if let Some(item) = current.buffer.pop_front() {
                return Ok(result(&item, false));
            }
            match current.chunks.take() {
                Some(chunks) => chunks,
                None => return Ok(result(&JsValue::UNDEFINED, true)),
            }
        };

        let chunk = chunks.next().await;
        let mut current = state.borrow_mut();
        if current.closed {
            return Ok(result(&JsValue::UNDEFINED, true));
        }
        match chunk {
            Some(Ok(items)) => {
                current.buffer.extend(items);
                current.chunks = Some(chunks);
            }
            Some(Err(error)) => return Err(error),
            None => return Ok(result(&JsValue::UNDEFINED, true)),
        }
    }
}

fn close(state: &Rc<RefCell<State>>, value: JsValue) -> Promise {
    let mut current = state.borrow_mut();
    current.closed = true;
    current.chunks = None;
    current.buffer.clear();
    Promise::resolve(&result(&value, true))
}

/// An iterator result, `{ value, done }`.
fn result(value: &JsValue, done: bool) -> JsValue {
    object(&[("value", value), ("done", &done.into())])
}

/// A plain object with `fields`.
fn object(fields: &[(&str, &JsValue)]) -> JsValue {
    let object = Object::new();
    for (key, value) in fields {
        set(&object, &(*key).into(), value);
    }
    object.into()
}

fn get(object: &Object, key: &JsValue) -> JsValue {
    Reflect::get(object, key).expect("a plain object has no throwing getters")
}

fn set(object: &Object, key: &JsValue, value: &JsValue) {
    Reflect::set(object, key, value).expect("a plain object has no throwing setters");
}
