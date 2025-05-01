use crate::utils::UnSend;

#[derive(Default)]
struct Target {
    _marker: std::marker::PhantomData<UnSend>,
}

impl Target {
    pub fn do_something(&self) {}
}

#[tokio::test]
pub async fn test_move_into_thread() {
    // let target = Target::default();

    // tokio::spawn(async move {
    //     target.do_something();
    //     // This should be a no-op, but it will panic if the object is not Send
    //     // let _ = value;

    //     // obj.do_something();
    // });
}
