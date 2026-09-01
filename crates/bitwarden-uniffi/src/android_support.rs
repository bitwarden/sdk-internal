use std::{error::Error, sync::OnceLock};

use jni::{
    jni_sig, jni_str,
    sys::{JavaVM, jint, jsize},
};
use tracing::{error, info};

pub static JAVA_VM: OnceLock<jni::JavaVM> = OnceLock::new();

// This function is called when the Android app calls `System.loadLibrary("bitwarden_uniffi")`
// Important: This function must be named `JNI_OnLoad` or otherwise it won't be called
#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub extern "system" fn JNI_OnLoad(
    vm_ptr: *mut jni::sys::JavaVM,
    _reserved: *mut std::ffi::c_void,
) -> jint {
    info!("JNI_OnLoad initializing");
    // SAFETY: `vm_ptr` is the JavaVM pointer the runtime passes to `JNI_OnLoad`; it is valid for
    // the whole lifetime of the process.
    let jvm = unsafe { jni::JavaVM::from_raw(vm_ptr) };
    JAVA_VM.get_or_init(|| jvm);
    jni::sys::JNI_VERSION_1_6
}

pub fn init() {
    fn init_inner() -> Result<(), Box<dyn Error>> {
        let jvm = match JAVA_VM.get() {
            Some(jvm) => {
                info!("JavaVM already initialized");
                jvm
            }
            None => {
                info!("JavaVM not initialized, initializing now");
                let jvm = java_vm()?;
                JAVA_VM.get_or_init(|| jvm)
            }
        };

        // Requesting a permanent attachment keeps the thread attached beyond the callback so later
        // JNI calls stay cheap. The borrowed `Env` is only valid inside the callback.
        jvm.attach_current_thread(|env| -> jni::errors::Result<()> {
            info!("Initializing Android verifier");
            init_verifier(env)
        })?;
        info!("SDK Android support initialized");
        Ok(())
    }

    if let Err(error) = init_inner() {
        error!(%error, "Failed to initialize Android support");
    }
}

type JniGetCreatedJavaVms =
    unsafe extern "system" fn(vmBuf: *mut *mut JavaVM, bufLen: jsize, nVMs: *mut jsize) -> jint;
const JNI_GET_JAVA_VMS_NAME: &[u8] = b"JNI_GetCreatedJavaVMs";

fn java_vm() -> Result<jni::JavaVM, Box<dyn Error>> {
    // Ideally we would use JNI to get a reference to the JavaVM, but that's not possible since
    // UniFFI uses JNA
    //
    // If we could use JNI, we'd just need to export a function and call it from the Android app:
    // #[export_name = "Java_com_orgname_android_rust_init"]
    // extern "C" fn java_init(env: JNIEnv, _class: JClass, context: JObject, ) -> jboolean {
    //
    // Instead we have to use libloading to get a reference to the JavaVM:
    //
    // https://github.com/mozilla/uniffi-rs/issues/1778#issuecomment-1807979746
    let lib = libloading::os::unix::Library::this();
    let get_created_java_vms: JniGetCreatedJavaVms = unsafe { *lib.get(JNI_GET_JAVA_VMS_NAME)? };

    let mut java_vms: [*mut JavaVM; 1] = [std::ptr::null_mut() as *mut JavaVM];
    let mut vm_count: i32 = 0;

    let ok = unsafe { get_created_java_vms(java_vms.as_mut_ptr(), 1, &mut vm_count) };
    if ok != jni::sys::JNI_OK {
        return Err("Failed to get JavaVM".into());
    }
    if vm_count != 1 {
        return Err(format!("Invalid JavaVM count: {vm_count}").into());
    }

    // SAFETY: `get_created_java_vms` reported exactly one JavaVM above, so `java_vms[0]` is a valid
    // pointer to the process' Java VM.
    let jvm = unsafe { jni::JavaVM::from_raw(java_vms[0]) };
    Ok(jvm)
}

fn init_verifier(env: &mut jni::Env<'_>) -> jni::errors::Result<()> {
    let activity_thread = env
        .call_static_method(
            jni_str!("android/app/ActivityThread"),
            jni_str!("currentActivityThread"),
            jni_sig!("()Landroid/app/ActivityThread;"),
            &[],
        )?
        .l()?;

    let context = env
        .call_method(
            &activity_thread,
            jni_str!("getApplication"),
            jni_sig!("()Landroid/app/Application;"),
            &[],
        )?
        .l()?;

    rustls_platform_verifier::android::init_with_env(env, context)
}
