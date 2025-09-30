use std::{error::Error, sync::OnceLock};

use jni::sys::{JavaVM, jint, jsize};

pub static JAVA_VM: OnceLock<jni::JavaVM> = OnceLock::new();

// This function is called when the Android app calls `System.loadLibrary("bitwarden_uniffi")`
// Important: This function must be named `JNI_OnLoad` or otherwise it won't be called
#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub extern "system" fn JNI_OnLoad(vm_ptr: jni::JavaVM, _reserved: *mut std::ffi::c_void) -> jint {
    log::info!("JNI_OnLoad initializing");
    JAVA_VM.get_or_init(|| vm_ptr);
    jni::sys::JNI_VERSION_1_6
}

pub fn init() {
    fn init_inner() -> Result<(), Box<dyn Error>> {
        let jvm = match JAVA_VM.get() {
            Some(jvm) => {
                log::info!("JavaVM already initialized");
                jvm
            }
            None => {
                log::info!("JavaVM not initialized, initializing now");
                let jvm = java_vm()?;
                JAVA_VM.get_or_init(|| jvm)
            }
        };

        let mut env = jvm.attach_current_thread_permanently()?;
        log::info!("Initializing Android verifier");
        init_verifier(&mut env)?;
        log::info!("SDK Android support initialized");
        Ok(())
    }

    if let Err(e) = init_inner() {
        log::error!("Failed to initialize Android support: {:#?}", e);
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

    let jvm = unsafe { jni::JavaVM::from_raw(java_vms[0]) }?;
    Ok(jvm)
}

fn init_verifier(env: &mut jni::JNIEnv<'_>) -> jni::errors::Result<()> {
    let activity_thread = env
        .call_static_method(
            "android/app/ActivityThread",
            "currentActivityThread",
            "()Landroid/app/ActivityThread;",
            &[],
        )?
        .l()?;

    let context = env
        .call_method(
            activity_thread,
            "getApplication",
            "()Landroid/app/Application;",
            &[],
        )?
        .l()?;

    Ok(rustls_platform_verifier::android::init_with_env(
        env, context,
    )?)
}
