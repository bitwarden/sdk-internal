use std::any::Any;

pub fn wrap(value: impl Any) -> Box<dyn Any> {
    Box::new(value)
}

pub fn try_unwrap<T: Any>(boxed: Box<dyn Any>) -> Option<T> {
    boxed.downcast::<T>().ok().map(|b| *b)
}

pub struct FunctionWrapper<Input> {
    function: Box<dyn FnOnce(Input) -> Box<dyn Any>>,
}

impl<Input> FunctionWrapper<Input> {
    pub fn new<F>(function: F) -> Self
    where
        F: FnOnce(Input) -> Box<dyn Any> + 'static,
    {
        FunctionWrapper {
            function: Box::new(function),
        }
    }

    pub fn wrap<F, Output>(function: F) -> Self
    where
        F: FnOnce(Input) -> Output + 'static,
        Output: 'static,
    {
        FunctionWrapper::new(move |input| {
            let result = function(input);
            wrap(result)
        })
    }

    pub fn call(self, input: Input) -> DynamicOutput {
        DynamicOutput::new((self.function)(input))
    }
}

// pub struct AsyncFunctionWrapper<Input> {
//     function: Box<dyn FnOnce(Input) -> Pin<Box<dyn Future<Output = Box<dyn Any>>>>>,
// }

// impl<Input> AsyncFunctionWrapper<Input> {
//     pub fn new<F>(function: F) -> Self
//     where
//         F: FnOnce(Input) -> Pin<Box<dyn Future<Output = Box<dyn Any>>> + 'static,
//     {
//         FunctionWrapper {
//             function: Box::new(function),
//         }
//     }

//     pub fn call(self, input: Input) -> DynamicOutput {
//         DynamicOutput::new((self.function)(input))
//     }
// }

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
        let wrapper = FunctionWrapper::new(|x: i32| wrap(x * 2));
        let result = wrapper.call(21);
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
                function.call(self.state)
            }
        }

        fn run_on_remote<Output>(
            remote: &RemoteObject,
            function: impl FnOnce(i32) -> Output + 'static,
        ) -> Box<Output>
        where
            Output: 'static,
        {
            let wrapped_function = FunctionWrapper::wrap(function);
            let dynamic_output = remote.run(wrapped_function);
            dynamic_output.get().expect("Failed to unwrap the output")
        }

        let remote_object = RemoteObject { state: 21 };

        let result = run_on_remote(&remote_object, |x: i32| x * 2);

        assert_eq!(result, Box::new(42));
    }
}
