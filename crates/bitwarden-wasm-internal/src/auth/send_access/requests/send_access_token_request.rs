/// Go to parent and import the necessary modules.
use super::super::enums::SendAccessCredentials;

const CLIENT_ID: &str = "";

pub struct SendAccessTokenRequest {
    pub send_id: String,
    pub send_access_credentials: Option<SendAccessCredentials>,
}

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

//   /**
//    * Builds the payload to send to /connect/token
//    */
//   // TODO: add tests for this method
//   toIdentityTokenPayload(): SendAccessTokenPayload {
//     const base: SendAccessTokenPayloadBase = {
//       client_id: SendAccessTokenRequest.CLIENT_ID,
//       grant_type: GrantType.SendAccess,
//       scope: Scope.Send,

//       send_id: this.sendId,
//     };

//     if (this.sendAccessCredentials && this.sendAccessCredentials.type === "password") {
//       return { ...base, password_hash: this.sendAccessCredentials.passwordHash };
//     } else if (this.sendAccessCredentials && this.sendAccessCredentials.type === "email") {
//       return { ...base, email: this.sendAccessCredentials.email };
//     } else if (this.sendAccessCredentials && this.sendAccessCredentials.type === "email-otp") {
//       return {
//         ...base,
//         email: this.sendAccessCredentials.email,
//         otp: this.sendAccessCredentials.otp,
//       };
//     } else {
//       return base;
//     }
//   }
