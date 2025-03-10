use crate::job::Job;

pub struct JobClient {
    jobs: Vec<Box<dyn Job>>,
}
