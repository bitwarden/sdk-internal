use super::super::enums::SendAccessClientType;
use super::super::enums::SendAccessTokenPayloadVariant;

// TODO: work with Dani to figure out serialization.
pub struct SendAccessTokenPayload {
    pub client_id: SendAccessClientType,
    pub grant_type: String,
    pub scope: String,
    pub send_id: String,
    pub variant: SendAccessTokenPayloadVariant,
}

// export type SendAccessTokenPasswordPayload = { password_hash: string };
// export type SendAccessTokenEmailPayload = { email: string };
// export type SendAccessTokenEmailOtpPayload = { email: string; otp: string };
// export type SendAccessTokenAnonymousPayload = object; // empty object

// export interface SendAccessTokenPayloadBase {
//   client_id: ClientType;
//   grant_type: GrantType;
//   scope: Scope;

//   send_id: string;
// }

// // Payload is the base + only 1 set of 3 credentials.
// export type SendAccessTokenPayload = SendAccessTokenPayloadBase &
//   (
//     | SendAccessTokenPasswordPayload
//     | SendAccessTokenEmailPayload
//     | SendAccessTokenEmailOtpPayload
//     | SendAccessTokenAnonymousPayload
//   );
