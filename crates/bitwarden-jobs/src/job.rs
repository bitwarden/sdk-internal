use std::future::Future;

pub struct JobInformation {
    pub id: uuid::Uuid,
    pub name: String,
    pub description: String,
    pub trigger: JobTrigger,
    pub concurrency: JobConcurrencyProtections,
    pub enabled: bool,
}

pub enum JobTrigger {
    Interval(String),
    Event(JobEventTrigger),
    Manual,
}

pub enum JobEventTrigger {
    /// Triggered whenever the vault is unlocked and all keys are available.
    VaultUnlock,
    /// Triggered whenever the vault is synced.
    VaultSynced,
    /// Triggered whenever the vault is synced and decryptable.
    VaultSyncedUnlocked,
    /// Triggered whenever a user enters the authenticated state. This can be used either after a successfull login
    /// or after a session is restored when the application restarts.
    UserAuthenticated,
    /// Triggered whenever a user is about to be logged out. The job will block the logout until it is finished,
    /// so be careful with long running jobs.
    UserLogout,
}

pub enum JobConcurrencyProtections {
    /// The job will not run if another instance of the job is already running on another device.
    /// from running on other devices. This guarantee can only be made if the device is online, meaning that
    /// this job will not run if the current device is offline.
    ///
    /// Note that concurrency protection might no be implemented on a per-job basis, meaning that
    /// the job might not run even if the trigger is fired and no other device is running it. For example,
    /// the system might assign a "current job runner" to a device and only allow that device to run the job.
    /// This means that the job will not run on other devices even if the trigger is fired on them.
    SingleInstancePerUser,
    /// The job will not run if another instance of the job is already running on the current device.
    /// Other devices might run the job at the same time. This job will run even if the device is offline.
    SingleInstancePerDevice,
    /// The job will always run when triggered.
    None,
}

pub enum JobRunError {
    JobFailed,
}

pub trait Job {
    fn get_information(&self) -> JobInformation;
    fn run(&self) -> impl Future<Output = Result<(), JobRunError>>;
}
