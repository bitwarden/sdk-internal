/// Credentials for sending password secured access requests.
#[derive(serde::Serialize)]
pub struct SendPasswordCredentials {
    pub password_hash: String,
}

/// Credentials for sending an OTP to the user's email address.
/// This is used when the send requires email verification with an OTP.
#[derive(serde::Serialize)]
pub struct SendEmailCredentials {
    pub email: String,
}

/// Credentials for getting a send access token using an email and OTP.
#[derive(serde::Serialize)]
pub struct SendEmailOtpCredentials {
    pub email: String,
    pub otp: String,
}

#[derive(serde::Serialize)]
#[serde(untagged)]
pub enum SendAccessCredentials {
    Password(SendPasswordCredentials),
    Email(SendEmailCredentials),
    EmailOtp(SendEmailOtpCredentials),
}
