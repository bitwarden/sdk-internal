cargo run -p uniffi-bindgen generate \
  ./sdk/src/main/jniLibs/arm64-v8a/libbitwarden_uniffi.so \
  --library \
  --language kotlin \
  --no-format \
  --out-dir sdk/src/main/java

# Insert a temporary alias for the deprecated Client type
ALIAS='
@Deprecated("Use PasswordManagerClient instead", ReplaceWith("PasswordManagerClient"))
typealias Client = PasswordManagerClient
'
echo -e "$ALIAS" >> ./sdk/src/main/java/com/bitwarden/sdk/bitwarden_uniffi.kt
