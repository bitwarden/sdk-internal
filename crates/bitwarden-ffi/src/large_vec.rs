//! [`LargeVec`], a list parameter converted from JavaScript item by item as it is read, and its
//! iterator.

use std::fmt;

/// A list parameter that converts a JavaScript array lazily, one item at a time. Use it for lists
/// that can be large, such as a vault's ciphers, and a plain `Vec` for the rest.
///
/// A regular `Vec<T>` converts the whole array as soon as JavaScript passes it in, which grows
/// WASM linear memory. WASM cannot give that memory back, so the allocation stays for the rest of
/// the session.
///
/// TypeScript sees `LargeVec<T>` as `T[]`, so `Vec` and `LargeVec` are interchangeable from
/// TypeScript's perspective. Rust and UniFFI callers wrap a regular `Vec` with `.into()`, which
/// does not copy it. Read the items by iterating over them, or take the Rust `Vec` back with
/// [`LargeVec::try_into_vec`].
pub struct LargeVec<T>(Items<T>);

enum Items<T> {
    Rust(Vec<T>),
    #[cfg(feature = "wasm")]
    Js(wasm::JsItems<T>),
}

impl<T> From<Vec<T>> for LargeVec<T> {
    fn from(items: Vec<T>) -> Self {
        Self(Items::Rust(items))
    }
}

impl<T> LargeVec<T> {
    /// The number of items.
    pub fn len(&self) -> usize {
        match &self.0 {
            Items::Rust(items) => items.len(),
            #[cfg(feature = "wasm")]
            Items::Js(items) => items.len(),
        }
    }

    /// Whether the list has no items.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The items as a `Vec`, when they came from Rust or UniFFI as one, or the list itself when
    /// they come from JavaScript.
    ///
    /// A `Vec` is already in memory, so a function can use it as a slice, which avoids moving
    /// each item out as iterating over the list does. Items from JavaScript are not converted
    /// yet, so for those the function iterates over the returned list.
    pub fn try_into_vec(self) -> Result<Vec<T>, Self> {
        match self.0 {
            Items::Rust(items) => Ok(items),
            #[cfg(feature = "wasm")]
            items @ Items::Js(_) => Err(Self(items)),
        }
    }
}

impl<T: 'static> LargeVec<T> {
    /// Applies `f` to each item: right away for items from Rust, and as each item is read for
    /// items from JavaScript.
    pub fn map<U: 'static>(self, f: impl Fn(T) -> U + Send + Sync + 'static) -> LargeVec<U> {
        LargeVec(match self.0 {
            Items::Rust(items) => Items::Rust(items.into_iter().map(f).collect()),
            #[cfg(feature = "wasm")]
            Items::Js(items) => Items::Js(items.map(f)),
        })
    }
}

impl<T> IntoIterator for LargeVec<T> {
    type Item = Result<T, LargeVecError>;
    type IntoIter = IntoIter<T>;

    fn into_iter(self) -> IntoIter<T> {
        IntoIter(match self.0 {
            Items::Rust(items) => Remaining::Rust(items.into_iter()),
            #[cfg(feature = "wasm")]
            Items::Js(items) => Remaining::Js(items),
        })
    }
}

/// The items of a [`LargeVec`] in order, one at a time, from its `into_iter` method.
///
/// Items from JavaScript are converted as they are reached. An item that fails to convert yields
/// one `Err` with its index and ends the iteration; the caller is expected to fail the whole call,
/// as wasm_bindgen does when it converts a `Vec<T>` parameter. Dropping the iterator releases the
/// handles of the items it has not reached.
pub struct IntoIter<T>(Remaining<T>);

/// What an [`IntoIter`] has left to yield.
enum Remaining<T> {
    Rust(std::vec::IntoIter<T>),
    #[cfg(feature = "wasm")]
    Js(wasm::JsItems<T>),
    /// An item failed to convert, which ends the iteration.
    #[cfg(feature = "wasm")]
    Done,
}

impl<T> Iterator for IntoIter<T> {
    type Item = Result<T, LargeVecError>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.0 {
            Remaining::Rust(items) => items.next().map(Ok),
            #[cfg(feature = "wasm")]
            Remaining::Js(items) => {
                let item = items.next_item()?;
                if item.is_err() {
                    self.0 = Remaining::Done;
                }
                Some(item)
            }
            #[cfg(feature = "wasm")]
            Remaining::Done => None,
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match &self.0 {
            Remaining::Rust(items) => items.size_hint(),
            // A failing item ends the iteration early, so only the upper bound is known.
            #[cfg(feature = "wasm")]
            Remaining::Js(items) => (0, Some(items.len())),
            #[cfg(feature = "wasm")]
            Remaining::Done => (0, Some(0)),
        }
    }
}

/// An item of a [`LargeVec`] does not convert to the item type.
#[derive(Debug)]
pub struct LargeVecError {
    index: usize,
    message: String,
}

impl fmt::Display for LargeVecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Item {} of the list is invalid: {}",
            self.index, self.message
        )
    }
}

impl std::error::Error for LargeVecError {}

#[cfg(feature = "wasm")]
mod wasm {
    use tsify::Tsify;
    use wasm_bindgen::{
        JsValue,
        convert::FromWasmAbi,
        describe::{WasmDescribe, WasmDescribeVector},
    };

    use super::{Items, LargeVec, LargeVecError};
    use crate::{FromWasm, WireError};

    /// Converts one item handle.
    type Convert<T> = Box<dyn Fn(JsValue) -> Result<T, String> + Send + Sync>;

    /// The item handles not yet converted, the index of the next one, and how to convert one.
    pub(super) struct JsItems<T> {
        items: std::vec::IntoIter<JsValue>,
        next: usize,
        convert: Convert<T>,
    }

    impl<T: 'static> JsItems<T> {
        /// Applies `f` to each item after it is converted.
        pub(super) fn map<U>(self, f: impl Fn(T) -> U + Send + Sync + 'static) -> JsItems<U> {
            let convert = self.convert;
            JsItems {
                items: self.items,
                next: self.next,
                convert: Box::new(move |value| convert(value).map(&f)),
            }
        }
    }

    impl<T> JsItems<T> {
        pub(super) fn len(&self) -> usize {
            self.items.len()
        }

        /// Converts the next item, or returns `None` once every item is read. Its handle is
        /// released as it is converted.
        pub(super) fn next_item(&mut self) -> Option<Result<T, LargeVecError>> {
            let value = self.items.next()?;
            let index = self.next;
            self.next += 1;
            Some((self.convert)(value).map_err(|message| LargeVecError { index, message }))
        }
    }

    /// Described as a `Vec` of the item's JavaScript type, so wasm_bindgen types the parameter
    /// `T[]` and generates the same JavaScript as for a `Vec<T>`. That type is a `JsCast` type,
    /// whose vector crosses as a list of value handles, the ABI `from_abi` takes over. Bounding on
    /// it, not on `T` itself, rules out a `T` such as `u8` whose vector crosses as raw bytes.
    impl<T> WasmDescribe for LargeVec<T>
    where
        T: Tsify,
        T::JsType: WasmDescribeVector,
    {
        fn describe() {
            <T::JsType as WasmDescribeVector>::describe_vector();
        }
    }

    impl<T> FromWasmAbi for LargeVec<T>
    where
        T: Tsify + serde::de::DeserializeOwned + 'static,
        T::JsType: WasmDescribeVector,
    {
        type Abi = <Box<[JsValue]> as FromWasmAbi>::Abi;

        /// Takes the array as one JavaScript value handle per item, four bytes each, and converts
        /// the items only when they are read.
        ///
        /// The generated JavaScript copies the handles when the call is made, as for a
        /// `Vec<JsValue>`, so changes the caller makes to the array after the call do not reach
        /// the items, which an `async` function reads later.
        unsafe fn from_abi(js: Self::Abi) -> Self {
            // SAFETY: `js` is the ABI form of a `Box<[JsValue]>`, as `describe` declares, so it is
            // taken over as wasm_bindgen takes over a `Vec<JsValue>` parameter.
            let items = unsafe { <Box<[JsValue]> as FromWasmAbi>::from_abi(js) };
            Self(Items::Js(JsItems {
                items: items.into_vec().into_iter(),
                next: 0,
                convert: Box::new(|value| T::from_js(value).map_err(|error| error.to_string())),
            }))
        }
    }

    /// Crosses as itself: the items convert when they are read, so there is nothing to convert
    /// at the boundary.
    impl<T> FromWasm for LargeVec<T>
    where
        T: Tsify + serde::de::DeserializeOwned + 'static,
        T::JsType: WasmDescribeVector,
    {
        type Wire = Self;

        fn from_wire(wire: Self) -> Result<Self, WireError> {
            Ok(wire)
        }
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;

    /// An item type for both builds: with the `wasm` feature, an item has to convert from
    /// JavaScript.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
    struct Item(u32);

    #[test]
    fn yields_the_items_of_a_rust_vec_in_order() {
        let list = LargeVec::from(vec![Item(1), Item(2), Item(3)]);

        let items: Vec<_> = list.into_iter().map(Result::unwrap).collect();

        assert_eq!(items, vec![Item(1), Item(2), Item(3)]);
    }

    #[test]
    fn hands_back_a_rust_vec() {
        let list = LargeVec::from(vec![Item(1), Item(2), Item(3)]);

        let items = list.try_into_vec().ok().unwrap();

        assert_eq!(items, vec![Item(1), Item(2), Item(3)]);
    }

    #[test]
    fn yields_no_items_for_an_empty_vec() {
        let list = LargeVec::<Item>::from(Vec::new());
        assert!(list.is_empty());

        assert_eq!(list.into_iter().count(), 0);
    }

    #[test]
    fn iterates_in_a_for_loop() {
        let list = LargeVec::from(vec![Item(1), Item(2)]);

        let mut items = Vec::new();
        for item in list {
            items.push(item.unwrap());
        }

        assert_eq!(items, vec![Item(1), Item(2)]);
    }

    #[test]
    fn maps_the_items_of_a_rust_vec() {
        let list = LargeVec::from(vec![Item(1), Item(2)]).map(|Item(n)| n * 10);

        let items: Vec<_> = list.into_iter().map(Result::unwrap).collect();

        assert_eq!(items, vec![10, 20]);
    }

    #[test]
    fn counts_items_without_a_conversion_bound() {
        /// Not an item type: it has no JavaScript conversion with the `wasm` feature.
        struct NotAnItem;

        let list = LargeVec::from(vec![NotAnItem, NotAnItem]);

        assert_eq!(list.len(), 2);
        assert!(!list.is_empty());
        assert_eq!(list.try_into_vec().ok().map(|items| items.len()), Some(2));
    }
}
