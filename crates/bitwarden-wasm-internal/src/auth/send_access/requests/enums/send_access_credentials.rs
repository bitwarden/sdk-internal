/// Credentials for sending password secured access requests.
pub struct SendPasswordCredentials {
    pub password_hash: String,
}

/// Credentials for sending an OTP to the user's email address.
/// This is used when the send requires email verification with an OTP.
pub struct SendEmailCredentials {
    pub email: String,
}

/// Credentials for getting a send access token using an email and OTP.
pub struct SendEmailOtpCredentials {
    pub email: String,
    pub otp: String,
}

pub enum SendAccessCredentials {
    Password(SendPasswordCredentials),
    Email(SendEmailCredentials),
    EmailOtp(SendEmailOtpCredentials),
}
