import BitwardenSdk
import Foundation

let TEST_EMAIL = "test@bitwarden.com"
let TEST_PASSWORD = "asdfasdfasdf"
let TEST_PIN = "1234"

let PRIVATE_KEY =
    "2.kmLY8NJVuiKBFJtNd/ZFpA==|qOodlRXER+9ogCe3yOibRHmUcSNvjSKhdDuztLlucs10jLiNoVVVAc+9KfNErLSpx5wmUF1hBOJM8zwVPjgQTrmnNf/wuDpwiaCxNYb/0v4FygPy7ccAHK94xP1lfqq7U9+tv+/yiZSwgcT+xF0wFpoxQeNdNRFzPTuD9o4134n8bzacD9DV/WjcrXfRjbBCzzuUGj1e78+A7BWN7/5IWLz87KWk8G7O/W4+8PtEzlwkru6Wd1xO19GYU18oArCWCNoegSmcGn7w7NDEXlwD403oY8Oa7ylnbqGE28PVJx+HLPNIdSC6YKXeIOMnVs7Mctd/wXC93zGxAWD6ooTCzHSPVV50zKJmWIG2cVVUS7j35H3rGDtUHLI+ASXMEux9REZB8CdVOZMzp2wYeiOpggebJy6MKOZqPT1R3X0fqF2dHtRFPXrNsVr1Qt6bS9qTyO4ag1/BCvXF3P1uJEsI812BFAne3cYHy5bIOxuozPfipJrTb5WH35bxhElqwT3y/o/6JWOGg3HLDun31YmiZ2HScAsUAcEkA4hhoTNnqy4O2s3yVbCcR7jF7NLsbQc0MDTbnjxTdI4VnqUIn8s2c9hIJy/j80pmO9Bjxp+LQ9a2hUkfHgFhgHxZUVaeGVth8zG2kkgGdrp5VHhxMVFfvB26Ka6q6qE/UcS2lONSv+4T8niVRJz57qwctj8MNOkA3PTEfe/DP/LKMefke31YfT0xogHsLhDkx+mS8FCc01HReTjKLktk/Jh9mXwC5oKwueWWwlxI935ecn+3I2kAuOfMsgPLkoEBlwgiREC1pM7VVX1x8WmzIQVQTHd4iwnX96QewYckGRfNYWz/zwvWnjWlfcg8kRSe+68EHOGeRtC5r27fWLqRc0HNcjwpgHkI/b6czerCe8+07TWql4keJxJxhBYj3iOH7r9ZS8ck51XnOb8tGL1isimAJXodYGzakwktqHAD7MZhS+P02O+6jrg7d+yPC2ZCuS/3TOplYOCHQIhnZtR87PXTUwr83zfOwAwCyv6KP84JUQ45+DItrXLap7nOVZKQ5QxYIlbThAO6eima6Zu5XHfqGPMNWv0bLf5+vAjIa5np5DJrSwz9no/hj6CUh0iyI+SJq4RGI60lKtypMvF6MR3nHLEHOycRUQbZIyTHWl4QQLdHzuwN9lv10ouTEvNr6sFflAX2yb6w3hlCo7oBytH3rJekjb3IIOzBpeTPIejxzVlh0N9OT5MZdh4sNKYHUoWJ8mnfjdM+L4j5Q2Kgk/XiGDgEebkUxiEOQUdVpePF5uSCE+TPav/9FIRGXGiFn6NJMaU7aBsDTFBLloffFLYDpd8/bTwoSvifkj7buwLYM+h/qcnfdy5FWau1cKav+Blq/ZC0qBpo658RTC8ZtseAFDgXoQZuksM10hpP9bzD04Bx30xTGX81QbaSTNwSEEVrOtIhbDrj9OI43KH4O6zLzK+t30QxAv5zjk10RZ4+5SAdYndIlld9Y62opCfPDzRy3ubdve4ZEchpIKWTQvIxq3T5ogOhGaWBVYnkMtM2GVqvWV//46gET5SH/MdcwhACUcZ9kCpMnWH9CyyUwYvTT3UlNyV+DlS27LMPvaw7tx7qa+GfNCoCBd8S4esZpQYK/WReiS8=|pc7qpD42wxyXemdNPuwxbh8iIaryrBPu8f/DGwYdHTw="

let MASTER_KEY_WRAPPED_USER_KEY =
    "2.u2HDQ/nH2J7f5tYHctZx6Q==|NnUKODz8TPycWJA5svexe1wJIz2VexvLbZh2RDfhj5VI3wP8ZkR0Vicvdv7oJRyLI1GyaZDBCf9CTBunRTYUk39DbZl42Rb+Xmzds02EQhc=|rwuo5wgqvTJf3rgwOUfabUyzqhguMYb3sGBjOYqjevc="

// PBKDF2 600k, V1 wrapped account state.
// Used by reinit tests that need a V1 client whose user key matches
// the V1 user key used to mint the captured upgrade-token vectors below.
let V1_ALIGNED_USER_ID = "060000fb-0922-4dd3-b170-6e15cb5df8c8"
let V1_ALIGNED_KDF_ITERATIONS: UInt32 = 600_000

let V1_ALIGNED_PRIVATE_KEY =
    "2.yN7l00BOlUE0Sb0M//Q53w==|EwKG/BduQRQ33Izqc/ogoBROIoI5dmgrxSo82sgzgAMIBt3A2FZ9vPRMY+GWT85JiqytDitGR3TqwnFUBhKUpRRAq4x7rA6A1arHrFp5Tp1p21O3SfjtvB3quiOKbqWk6ZaU1Np9HwqwAecddFcB0YyBEiRX3VwF2pgpAdiPbSMuvo2qIgyob0CUoC/h4Bz1be7Qa7B0Xw9/fMKkB1LpOm925lzqosyMQM62YpMGkjMsbZz0uPopu32fxzDWSPr+kekNNyLt9InGhTpxLmq1go/pXR2uw5dfpXc5yuta7DB0EGBwnQ8Vl5HPdDooqOTD9I1jE0mRyuBpWTTI3FRnu3JUh3rIyGBJhUmHqGZvw2CKdqHCIrQeQkkEYqOeJRJVdBjhv5KGJifqT3BFRwX/YFJIChAQpebNQKXe/0kPivWokHWwXlDB7S7mBZzhaAPidZvnuIhalE2qmTypDwHy22FyqV58T8MGGMchcASDi/QXI6kcdpJzPXSeU9o+NC68QDlOIrMVxKFeE7w7PvVmAaxEo0YwmuAzzKy9QpdlK0aab/xEi8V4iXj4hGepqAvHkXIQd+r3FNeiLfllkb61p6WTjr5urcmDQMR94/wYoilpG5OlybHdbhsYHvIzYoLrC7fzl630gcO6t4nM24vdB6Ymg9BVpEgKRAxSbE62Tqacxqnz9AcmgItb48NiR/He3n3ydGjPYuKk/ihZMgEwAEZvSlNxYONSbYrIGDtOY+8Nbt6KiH3l06wjZW8tcmFeVlWv+tWotnTY9IqlAfvNVTjtsobqtQnvsiDjdEVtNy/s2ci5TH+NdZluca2OVEr91Wayxh70kpM6ib4UGbfdmGgCo74gtKvKSJU0rTHakQ5L9JlaSDD5FamBRyI0qfL43Ad9qOUZ8DaffDCyuaVyuqk7cz9HwmEmvWU3VQ+5t06n/5kRDXttcw8w+3qClEEdGo1KeENcnXCB32dQe3tDTFpuAIMLqwXs6FhpawfZ5kPYvLPczGWaqftIs/RXJ/EltGc0ugw2dmTLpoQhCqrcKEBDoYVk0LDZKsnzitOGdi9mOWse7Se8798ib1UsHFUjGzISEt6upestxOeupSTOh0v4+AjXbDzRUyogHww3V+Bqg71bkcMxtB+WM+pn1XNbVTyl9NR040nhP7KEf6e9ruXAtmrBC2ah5cFEpLIot77VFZ9ilLuitSz+7T8n1yAh1IEG6xxXxninAZIzi2qGbH69O5RSpOJuJTv17zTLJQIIc781JwQ2TTwTGnx5wZLbffhCasowJKd2EVcyMJyhz6ru0PvXWJ4hUdkARJs3Xu8dus9a86N8Xk6aAPzBDqzYb1vyFIfBxP0oO8xFHgd30Cgmz8UrSE3qeWRrF8ftrI6xQnFjHBGWD/JWSvd6YMcQED0aVuQkuNW9ST/DzQThPzRfPUoiL10yAmV7Ytu4fR3x2sF0Yfi87YhHFuCMpV/DsqxmUizyiJuD938eRcH8hzR/VO53Qo3UIsqOLcyXtTv6THjSlTopQ+JOLOnHm1w8dzYbLN44OG44rRsbihMUQp+wUZ6bsI8rrOnm9WErzkbQFbrfAINdoCiNa6cimYIjvvnMTaFWNymqY1vZxGztQiMiHiHYwTfwHTXrb9j0uPM=|09J28iXv9oWzYtzK2LBT6Yht4IT4MijEkk0fwFdrVQ4="

let V1_ALIGNED_MASTER_KEY_WRAPPED_USER_KEY =
    "2.Q/2PhzcC7GdeiMHhWguYAQ==|GpqzVdr0go0ug5cZh1n+uixeBC3oC90CIe0hd/HWA/pTRDZ8ane4fmsEIcuc8eMKUt55Y2q/fbNzsYu41YTZzzsJUSeqVjT8/iTQtgnNdpo=|dwI+uyvZ1h/iZ03VQ+/wrGEFYVewBUUl/syYgjsNMbE="

// V2 wrapped account state and as the expected user key after V1→V2 reinit.
let TEST_VECTOR_USER_KEY_V2_B64 =
    "pQEEAlACHUUoybNAuJoZzqNMxz2bAzoAARFvBIQDBAUGIFggAvGl4ifaUAomQdCdUPpXLHtypiQxHjZwRHeI83caZM4B"

let TEST_VECTOR_PRIVATE_KEY_V2 =
    "7.g1gdowE6AAERbwMZARwEUAIdRSjJs0C4mhnOo0zHPZuhBVgYthGLGqVLPeidY8mNMxpLJn3fyeSxyaWsWQTR6pxmRV2DyGZXly/0l9KK+Rsfetl9wvYIz0O4/RW3R6wf7eGxo5XmicV3WnFsoAmIQObxkKWShxFyjzg+ocKItQDzG7Gp6+MW4biTrAlfK51ML/ZS+PCjLmgI1QQr4eMHjiwA2TBKtKkxfjoTJkMXECpRVLEXOo8/mbIGYkuabbSA7oU+TJ0yXlfKDtD25gnyO7tjW/0JMFUaoEKRJOuKoXTN4n/ks4Hbxk0X5/DzfG05rxWad2UNBjNg7ehW99WrQ+33ckdQFKMQOri/rt8JzzrF1k11/jMJ+Y2TADKNHr91NalnUX+yqZAAe3sRt5Pv5ZhLIwRMKQi/1NrLcsQPRuUnogVSPOoMnE/eD6F70iU60Z6pvm1iBw2IvELZcrs/oxpO2SeCue08fIZW/jNZokbLnm90tQ7QeZTUpiPALhUgfGOa3J9VOJ7jQGCqDjd9CzV2DCVfhKCapeTbldm+RwEWBz5VvorH5vMx1AzbPRJxdIQuxcg3NqRrXrYC7fyZljWaPB9qP1tztiPtd1PpGEgxLByIfR6fqyZMCvOBsWbd0H6NhF8mNVdDw60+skFRdbRBTSCjCtKZeLVuVFb8ioH45PR5oXjtx4atIDzu6DKm6TTMCbR6DjZuZZ8GbwHxuUD2mDD3pAFhaof9kR3lQdjy7Zb4EzUUYskQxzcLPcqzp9ZgB3Rg91SStBCCMhdQ6AnhTy+VTGt/mY5AbBXNRSL6fI0r+P9K8CcEI4bNZCDkwwQr5v4O4ykSUzIvmVU0zKzDngy9bteIZuhkvGUoZlQ9UATNGPhoLfqq2eSvqEXkCbxTVZ5D+Ww9pHmWeVcvoBhcl5MvicfeQt++dY3tPjIfZq87nlugG4HiNbcv9nbVpgwe3v8cFetWXQgnO4uhx8JHSwGoSuxHFZtl2sdahjTHavRHnYjSABEFrViUKgb12UDD5ow1GAL62wVdSJKRf9HlLbJhN3PBxuh5L/E0wy1wGA9ecXtw/R1ktvXZ7RklGAt1TmNzZv6vI2J/CMXvndOX9rEpjKMbwbIDAjQ9PxiWdcnmc5SowT9f6yfIjbjXnRMWWidPAua7sgrtej4HP4Qjz1fpgLMLCRyF97tbMTmsAI5Cuj98Buh9PwcdyXj5SbVuHdJS1ehv9b5SWPsD4pwOm3+otVNK6FTazhoUl47AZoAoQzXfsXxrzqYzvF0yJkCnk9S1dcij1L569gQ43CJO6o6jIZFJvA4EmZDl95ELu+BC+x37Ip8dq4JLPsANDVSqvXO9tfDUIXEx25AaOYhW2KAUoDve/fbsU8d0UZR1o/w+ZrOQwawCIPeVPtbh7KFRVQi/rPI+Abl6XR6qMJbKPegliYGUuGF2oEMEc6QLTsMRCEPuw0S3kxbNfVPqml8nGhB2r8zUHBY1diJEmipVghnwH74gIKnyJ2C9nKjV8noUfKzqyV8vxUX2G5yXgodx8Jn0cWs3XhWuApFla9z4R28W/4jA1jK2WQMlx+b6xKUWgRk8+fYsc0HSt2fDrQ9pLpnjb8ME59RCxSPV++PThpnR2JtastZBZur2hBIJsGILCAmufUU4VC4gBKPhNfu/OK4Ktgz+uQlUa9fEC/FnkpTRQPxHuQjSQSNrIIyW1bIRBtnwjvvvNoui9FZJ"

let TEST_VECTOR_SIGNING_KEY_V2 =
    "7.g1gcowE6AAERbwMYZQRQAh1FKMmzQLiaGc6jTMc9m6EFWBhYePc2qkCruHAPXgbzXsIP1WVk11ArbLNYUBpifToURlwHKs1je2BwZ1C/5thz4nyNbL0wDaYkRWI9ex1wvB7KhdzC7ltStEd5QttboTSCaXQROSZaGBPNO5+Bu3sTY8F5qK1pBUo6AHNN"

let TEST_VECTOR_SECURITY_STATE_V2 =
    "hFgepAEnAxg8BFAmkP0QgfdMVbIujX55W/yNOgABOH8CoFgkomhlbnRpdHlJZFBHOOw2BI9OQoNq+Vl1xZZKZ3ZlcnNpb24CWEAlchbJR0vmRfShG8On7Q2gknjkw4Dd6MYBLiH4u+/CmfQdmjNZdf6kozgW/6NXyKVNu8dAsKsin+xxXkDyVZoG"

let TEST_VECTOR_SIGNED_PUBLIC_KEY_V2 =
    "hFgepAEnAxg8BFAmkP0QgfdMVbIujX55W/yNOgABOH8BoFkBTqNpYWxnb3JpdGhtAG1jb250ZW50Rm9ybWF0AGlwdWJsaWNLZXlZASYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDP/7WM8nUepxoJ0qtM+azxcly+eZ31qUjjZTZcX/gYw1MzkoXWAjqyeFH/bdktq1lEUwegrxkIxKkY2SMtp0CvPnaV1x5O8E6FBSJbKWRlDg181rfEhgm5tc6aR4PJ827IvFVm9xk6Sj091P5DHZDEOsWLZc2jYjtpUV3X38I4gSR7HiYnR4DcwcWkoJ3FhtxMCwYgPz6RVH0vzhLUmm1mgbzH6IH8Pf9DjLTZSxBikVO7S9s9jzhiZbTeeAl3FbNLxfj9Qkj+NoSfms7jGVTlBwvSXgjJs/ktGkT1cR5QcBMpU4bt41+l73MN8pXapCih9Awf1W+RY7imxpYOMFJ3AgMBAAFYQMq/hT4wod2w8xyoM7D86ctuLNX4ZRo+jRHf2sZfaO7QsvonG/ZYuNKF5fq8wpxMRjfoMvnY2TTShbgzLrW8BA4="

// Captured V2 upgrade-token vectors
let VALID_UPGRADE_TOKEN_WRAPPED_UK1 =
    "7.g1g+owE6AAERbwN4ImFwcGxpY2F0aW9uL3guYml0d2FyZGVuLmxlZ2FjeS1rZXkEUAIdRSjJs0C4mhnOo0zHPZuhBVgY1qXqPCYn/5nABkxco5vQWQNu14TfOHFOWFBMa4lmTgFGHZ4tHpoPQdeAUdMuNpm/I5FKUN/chFhlQMvF8Ytr/pnvj8AUMYgFtVbrq6fwbLKOdgHjdKglnP7iS+MWhHpfA17KMQDdsqS6Jw=="

let VALID_UPGRADE_TOKEN_WRAPPED_UK2 =
    "2.ou/hhj/jC24Msfu4fQXuFg==|Kb5LkKf7vQ2EOcAuckoeYfdmhAaoS3H6sisTDliCQRPp2vw3HmgQQ8fznI+H7Q3itsNA0XuPSa/7PMFhAvJlCjFlrPBiNGBsmOzqmjQaDKk=|jZ1+9z59BO2SdbUuHk20qTD73SzNNR9bq9a2pXNPNG0="

let MISMATCHED_UPGRADE_TOKEN_WRAPPED_UK1 =
    "7.g1g+owE6AAERbwN4ImFwcGxpY2F0aW9uL3guYml0d2FyZGVuLmxlZ2FjeS1rZXkEUNol5XO6EzJktdaId2onuz2hBVgYmy5gZfg+aRarn89+BYJLsLBUh5p3ohdOWFC/KmhUg1EheyIAbKkVKdf1FbYseBTsY2kRJEmc1n94iFo+DJ84rbLgj0Aa6O3JU+swo7zFyh6qc4//wfn7yBJotXpfgs6nzIYlsAKVVdJNmA=="

let MISMATCHED_UPGRADE_TOKEN_WRAPPED_UK2 =
    "2.NOlQoDKNd5Ly6fsIe9HD9Q==|QRTJqoRQsB9LoxPb+FMQGeXvA4p5k0Lw2XakpdyIqWnt7YKWrRXy7wg5YukZLFb/R/GAd4YM21GNNLD+zHz7vXXPTAlb1OQa23wpg2ediX4=|3dr1tYlbUDjQ0lRZLdKZTe3Jjdv/NR7S7zOb1YPCRJ8="

/// In-memory `StateBridgeForeignImpl` for tests. Mirrors `makeStateBridge()`
/// from the WASM integration tests.
actor InMemoryStateBridge: StateBridgeForeignImpl {
    private var userKey: SymmetricCryptoKey?
    private var persistentPinEnvelope: PasswordProtectedKeyEnvelope?
    private var ephemeralPinEnvelope: PasswordProtectedKeyEnvelope?
    private var encryptedPin: EncString?
    private var v2UpgradeToken: V2UpgradeToken?
    private var accountCryptographicState: WrappedAccountCryptographicState?
    private var masterpasswordUnlockData: MasterPasswordUnlockData?

    func setUserKey(value: SymmetricCryptoKey) { userKey = value }
    func getUserKey() -> SymmetricCryptoKey? { userKey }
    func clearUserKey() { userKey = nil }

    func setPersistentPinEnvelope(value: PasswordProtectedKeyEnvelope) { persistentPinEnvelope = value }
    func getPersistentPinEnvelope() -> PasswordProtectedKeyEnvelope? { persistentPinEnvelope }
    func clearPersistentPinEnvelope() { persistentPinEnvelope = nil }

    func setEphemeralPinEnvelope(value: PasswordProtectedKeyEnvelope) { ephemeralPinEnvelope = value }
    func getEphemeralPinEnvelope() -> PasswordProtectedKeyEnvelope? { ephemeralPinEnvelope }
    func clearEphemeralPinEnvelope() { ephemeralPinEnvelope = nil }

    func setEncryptedPin(value: EncString) { encryptedPin = value }
    func getEncryptedPin() -> EncString? { encryptedPin }
    func clearEncryptedPin() { encryptedPin = nil }

    func setV2UpgradeToken(value: V2UpgradeToken) { v2UpgradeToken = value }
    func getV2UpgradeToken() -> V2UpgradeToken? { v2UpgradeToken }
    func clearV2UpgradeToken() { v2UpgradeToken = nil }

    func setAccountCryptographicState(value: WrappedAccountCryptographicState) { accountCryptographicState = value }
    func getAccountCryptographicState() -> WrappedAccountCryptographicState? { accountCryptographicState }
    func clearAccountCryptographicState() { accountCryptographicState = nil }

    func setMasterpasswordUnlockData(value: MasterPasswordUnlockData) { masterpasswordUnlockData = value }
    func getMasterpasswordUnlockData() -> MasterPasswordUnlockData? { masterpasswordUnlockData }
    func clearMasterpasswordUnlockData() { masterpasswordUnlockData = nil }
}

final class MockTokenProvider: ClientManagedTokens {
    func getAccessToken() async -> String? { nil }
}

/// Builds a `Client` with a registered `InMemoryStateBridge` and an initialized
/// crypto state, mirroring `makeInitializedPasswordmanagerClient` from the WASM
/// integration tests.
func makeInitializedClient(stateBridge: InMemoryStateBridge) async throws -> Client {
    let client = Client(tokenProvider: MockTokenProvider(), settings: nil)
    client.kmStateBridge().registerBridgeImpl(bridgeImpl: stateBridge)

    let req = InitUserCryptoRequest(
        userId: "00000000-0000-0000-0000-000000000000",
        kdfParams: .pbkdf2(iterations: 100_000),
        email: TEST_EMAIL,
        accountCryptographicState: .v1(privateKey: PRIVATE_KEY),
        method: .masterPasswordUnlock(
            password: TEST_PASSWORD,
            masterPasswordUnlock: MasterPasswordUnlockData(
                kdf: .pbkdf2(iterations: 100_000),
                masterKeyWrappedUserKey: MASTER_KEY_WRAPPED_USER_KEY,
                salt: TEST_EMAIL
            )
        ),
        upgradeToken: nil
    )

    try await client.crypto().initializeUserCrypto(req: req)
    return client
}

/// Builds a V1 `Client` matching the `test_bitwarden_com_account` Rust fixture
/// (PBKDF2 600k, V1 wrapped account state). The resulting in-memory V1 user key
/// is the one used to mint `VALID_UPGRADE_TOKEN_WRAPPED_UK*`.
func makeV1AlignedClient(stateBridge: InMemoryStateBridge) async throws -> Client {
    let client = Client(tokenProvider: MockTokenProvider(), settings: nil)
    client.kmStateBridge().registerBridgeImpl(bridgeImpl: stateBridge)

    let req = InitUserCryptoRequest(
        userId: V1_ALIGNED_USER_ID,
        kdfParams: .pbkdf2(iterations: V1_ALIGNED_KDF_ITERATIONS),
        email: TEST_EMAIL,
        accountCryptographicState: .v1(privateKey: V1_ALIGNED_PRIVATE_KEY),
        method: .masterPasswordUnlock(
            password: TEST_PASSWORD,
            masterPasswordUnlock: MasterPasswordUnlockData(
                kdf: .pbkdf2(iterations: V1_ALIGNED_KDF_ITERATIONS),
                masterKeyWrappedUserKey: V1_ALIGNED_MASTER_KEY_WRAPPED_USER_KEY,
                salt: TEST_EMAIL
            )
        ),
        upgradeToken: nil
    )

    try await client.crypto().initializeUserCrypto(req: req)
    return client
}

/// Builds a V2 `Client` matching the `test_bitwarden_com_account_v2` Rust fixture
/// (Argon2id, V2 wrapped account state, user key seeded via `DecryptedKey`).
func makeV2InitializedClient(stateBridge: InMemoryStateBridge) async throws -> Client {
    let client = Client(tokenProvider: MockTokenProvider(), settings: nil)
    client.kmStateBridge().registerBridgeImpl(bridgeImpl: stateBridge)

    let req = InitUserCryptoRequest(
        userId: V1_ALIGNED_USER_ID,
        kdfParams: .argon2id(iterations: 6, memory: 32, parallelism: 4),
        email: TEST_EMAIL,
        accountCryptographicState: makeV2AccountCryptographicState(),
        method: .decryptedKey(decryptedUserKey: TEST_VECTOR_USER_KEY_V2_B64),
        upgradeToken: nil
    )

    try await client.crypto().initializeUserCrypto(req: req)
    return client
}

/// V2 wrapped account state from the test vectors. Decrypts cleanly only when
/// paired with the V2 user key (`TEST_VECTOR_USER_KEY_V2_B64`).
func makeV2AccountCryptographicState() -> WrappedAccountCryptographicState {
    .v2(
        privateKey: TEST_VECTOR_PRIVATE_KEY_V2,
        signedPublicKey: TEST_VECTOR_SIGNED_PUBLIC_KEY_V2,
        signingKey: TEST_VECTOR_SIGNING_KEY_V2,
        securityState: TEST_VECTOR_SECURITY_STATE_V2
    )
}

/// Builds a `V2UpgradeToken` from the captured valid wrapped strings. Pairs
/// with the V1 user key derived from `makeV1AlignedClient`.
func makeValidUpgradeToken() -> V2UpgradeToken {
    V2UpgradeToken(
        wrappedUserKey1: VALID_UPGRADE_TOKEN_WRAPPED_UK1,
        wrappedUserKey2: VALID_UPGRADE_TOKEN_WRAPPED_UK2
    )
}

/// Structurally valid `V2UpgradeToken` whose wrapped keys are bound to unrelated
/// V1/V2 keys, so unwrapping with the V1-aligned client's user key fails.
/// Useful both for the `InvalidUpgradeToken` test and as a placeholder where
/// reinit is expected to error out before unwrapping.
func makeDummyUpgradeToken() -> V2UpgradeToken {
    V2UpgradeToken(
        wrappedUserKey1: MISMATCHED_UPGRADE_TOKEN_WRAPPED_UK1,
        wrappedUserKey2: MISMATCHED_UPGRADE_TOKEN_WRAPPED_UK2
    )
}
