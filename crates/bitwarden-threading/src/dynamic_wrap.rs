use std::{any::Any, future::Future, pin::Pin, sync::Arc};

pub fn wrap(value: impl Any) -> Box<dyn Any> {
    Box::new(value)
}

pub fn try_unwrap<T: Any>(boxed: Box<dyn Any>) -> Option<T> {
    boxed.downcast::<T>().ok().map(|b| *b)
}

// pub fn pin_wrap(value: impl Any) -> Pin<Box<dyn Any>> {
//     Box::pin(value)
// }

// pub fn try_pin_unwrap<T: Any + Unpin>(boxed: Pin<Box<dyn Any>>) -> Option<T> {
//     // We need to convert the Pin<Box<dyn Any>> to a Box<dyn Any> first
//     // and then downcast it to the desired type
//     // This is safe because we are the only owner of the Pin<Box<dyn Any>>
//     // and we know that it is safe to convert it to a Box<dyn Any>

//     let unpinned = boxed.
// }

pub struct FunctionWrapper<Input> {
    function: Box<dyn FnOnce(&Input) -> Box<dyn Any>>,
}

impl<Input> FunctionWrapper<Input> {
    pub fn new<F>(function: F) -> Self
    where
        F: FnOnce(&Input) -> Box<dyn Any> + 'static,
    {
        FunctionWrapper {
            function: Box::new(function),
        }
    }

    pub fn wrap<F, Output>(function: F) -> Self
    where
        F: FnOnce(&Input) -> Output + 'static,
        Output: 'static,
    {
        FunctionWrapper::new(move |input| {
            let result = function(input);
            wrap(result)
        })
    }

    pub fn call(self, input: &Input) -> DynamicOutput {
        DynamicOutput::new((self.function)(input))
    }
}

pub struct AsyncFunctionWrapper<Input> {
    function: Box<dyn FnOnce(Arc<Input>) -> Pin<Box<dyn Future<Output = Box<dyn Any>>>>>,
}

impl<Input> AsyncFunctionWrapper<Input> {
    pub fn new<F>(function: F) -> Self
    where
        F: FnOnce(Arc<Input>) -> Pin<Box<dyn Future<Output = Box<dyn Any>>>> + 'static,
    {
        AsyncFunctionWrapper {
            function: Box::new(function),
        }
    }

    pub fn wrap<F, Output>(function: F) -> Self
    where
        F: FnOnce(Arc<Input>) -> Pin<Box<dyn Future<Output = Output>>> + 'static,
        Input: 'static,
        Output: 'static,
    {
        AsyncFunctionWrapper::new(move |input: Arc<Input>| {
            let input = input.clone();
            Box::pin(async move {
                let result = function(input).await;
                wrap(result)
            })
        })
    }

    pub async fn call(self, input: Arc<Input>) -> DynamicOutput {
        let result = (self.function)(input).await;
        DynamicOutput::new(result)
    }
}

pub struct DynamicOutput {
    value: Box<dyn Any + 'static>,
}

impl DynamicOutput {
    pub fn new(value: Box<dyn Any>) -> Self {
        DynamicOutput { value }
    }

    pub fn get<T: Any>(self) -> Result<Box<T>, Box<(dyn Any + 'static)>> {
        self.value.downcast::<T>()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_wrap() {
        let value = 42;
        let wrapped = wrap(value);
        let unwrapped: Option<i32> = try_unwrap(wrapped);
        assert_eq!(unwrapped, Some(42));
    }

    #[test]
    fn test_function_wrapper() {
        let wrapper = FunctionWrapper::new(|x: &i32| wrap(x * 2));
        let result = wrapper.call(&21);
        let unwrapped: Box<i32> = result.get().unwrap();
        assert_eq!(unwrapped, Box::new(42));
    }

    #[test]
    fn test_function_wrapper_remote_execution() {
        struct RemoteObject {
            state: i32,
        }

        impl RemoteObject {
            pub fn run(&self, function: FunctionWrapper<i32>) -> DynamicOutput {
                function.call(&self.state)
            }
        }

        fn run_on_remote<Output>(
            remote: &RemoteObject,
            function: impl FnOnce(&i32) -> Output + 'static,
        ) -> Box<Output>
        where
            Output: 'static,
        {
            let wrapped_function = FunctionWrapper::wrap(function);
            let dynamic_output = remote.run(wrapped_function);
            dynamic_output.get().expect("Failed to unwrap the output")
        }

        let remote_object = RemoteObject { state: 21 };

        let result = run_on_remote(&remote_object, |x: &i32| x * 2);

        assert_eq!(result, Box::new(42));
    }

    #[tokio::test]
    async fn test_async_function_wrapper_remote_execution() {
        struct RemoteObject {
            state: Arc<i32>,
        }

        impl RemoteObject {
            pub async fn run(&self, function: AsyncFunctionWrapper<i32>) -> DynamicOutput {
                function.call(self.state.clone()).await
            }
        }

        async fn run_on_remote<Output>(
            remote: &RemoteObject,
            function: impl FnOnce(Arc<i32>) -> Pin<Box<dyn Future<Output = Output>>> + 'static,
        ) -> Box<Output>
        where
            Output: 'static,
        {
            let wrapped_function = AsyncFunctionWrapper::wrap(function);
            let dynamic_output = remote.run(wrapped_function).await;
            dynamic_output.get().expect("Failed to unwrap the output")
        }

        let remote_object = RemoteObject {
            state: Arc::new(21),
        };

        let result = run_on_remote(&remote_object, |x: Arc<i32>| {
            Box::pin(async move { x.clone().as_ref() * 2 })
        })
        .await;

        assert_eq!(result, Box::new(42));
    }
}
