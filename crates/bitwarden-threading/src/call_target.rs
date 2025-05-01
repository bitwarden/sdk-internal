use std::future::Future;

pub trait CallTarget {
    type Input: Send + 'static;
    type Output: Send + 'static;

    fn call(&self, input: Self::Input) -> impl Future<Output = Self::Output>;
}
