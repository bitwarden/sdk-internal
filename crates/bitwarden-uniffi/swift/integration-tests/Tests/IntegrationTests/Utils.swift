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
let TEST_VECTOR_USER_ID_V1 = "060000fb-0922-4dd3-b170-6e15cb5df8c8"
let TEST_VECTOR_KDF_ITERATIONS_V1: UInt32 = 600_000

let TEST_VECTOR_PRIVATE_KEY_V1 =
    "2.yN7l00BOlUE0Sb0M//Q53w==|EwKG/BduQRQ33Izqc/ogoBROIoI5dmgrxSo82sgzgAMIBt3A2FZ9vPRMY+GWT85JiqytDitGR3TqwnFUBhKUpRRAq4x7rA6A1arHrFp5Tp1p21O3SfjtvB3quiOKbqWk6ZaU1Np9HwqwAecddFcB0YyBEiRX3VwF2pgpAdiPbSMuvo2qIgyob0CUoC/h4Bz1be7Qa7B0Xw9/fMKkB1LpOm925lzqosyMQM62YpMGkjMsbZz0uPopu32fxzDWSPr+kekNNyLt9InGhTpxLmq1go/pXR2uw5dfpXc5yuta7DB0EGBwnQ8Vl5HPdDooqOTD9I1jE0mRyuBpWTTI3FRnu3JUh3rIyGBJhUmHqGZvw2CKdqHCIrQeQkkEYqOeJRJVdBjhv5KGJifqT3BFRwX/YFJIChAQpebNQKXe/0kPivWokHWwXlDB7S7mBZzhaAPidZvnuIhalE2qmTypDwHy22FyqV58T8MGGMchcASDi/QXI6kcdpJzPXSeU9o+NC68QDlOIrMVxKFeE7w7PvVmAaxEo0YwmuAzzKy9QpdlK0aab/xEi8V4iXj4hGepqAvHkXIQd+r3FNeiLfllkb61p6WTjr5urcmDQMR94/wYoilpG5OlybHdbhsYHvIzYoLrC7fzl630gcO6t4nM24vdB6Ymg9BVpEgKRAxSbE62Tqacxqnz9AcmgItb48NiR/He3n3ydGjPYuKk/ihZMgEwAEZvSlNxYONSbYrIGDtOY+8Nbt6KiH3l06wjZW8tcmFeVlWv+tWotnTY9IqlAfvNVTjtsobqtQnvsiDjdEVtNy/s2ci5TH+NdZluca2OVEr91Wayxh70kpM6ib4UGbfdmGgCo74gtKvKSJU0rTHakQ5L9JlaSDD5FamBRyI0qfL43Ad9qOUZ8DaffDCyuaVyuqk7cz9HwmEmvWU3VQ+5t06n/5kRDXttcw8w+3qClEEdGo1KeENcnXCB32dQe3tDTFpuAIMLqwXs6FhpawfZ5kPYvLPczGWaqftIs/RXJ/EltGc0ugw2dmTLpoQhCqrcKEBDoYVk0LDZKsnzitOGdi9mOWse7Se8798ib1UsHFUjGzISEt6upestxOeupSTOh0v4+AjXbDzRUyogHww3V+Bqg71bkcMxtB+WM+pn1XNbVTyl9NR040nhP7KEf6e9ruXAtmrBC2ah5cFEpLIot77VFZ9ilLuitSz+7T8n1yAh1IEG6xxXxninAZIzi2qGbH69O5RSpOJuJTv17zTLJQIIc781JwQ2TTwTGnx5wZLbffhCasowJKd2EVcyMJyhz6ru0PvXWJ4hUdkARJs3Xu8dus9a86N8Xk6aAPzBDqzYb1vyFIfBxP0oO8xFHgd30Cgmz8UrSE3qeWRrF8ftrI6xQnFjHBGWD/JWSvd6YMcQED0aVuQkuNW9ST/DzQThPzRfPUoiL10yAmV7Ytu4fR3x2sF0Yfi87YhHFuCMpV/DsqxmUizyiJuD938eRcH8hzR/VO53Qo3UIsqOLcyXtTv6THjSlTopQ+JOLOnHm1w8dzYbLN44OG44rRsbihMUQp+wUZ6bsI8rrOnm9WErzkbQFbrfAINdoCiNa6cimYIjvvnMTaFWNymqY1vZxGztQiMiHiHYwTfwHTXrb9j0uPM=|09J28iXv9oWzYtzK2LBT6Yht4IT4MijEkk0fwFdrVQ4="

let TEST_VECTOR_MASTER_KEY_WRAPPED_USER_KEY_V1 =
    "2.Q/2PhzcC7GdeiMHhWguYAQ==|GpqzVdr0go0ug5cZh1n+uixeBC3oC90CIe0hd/HWA/pTRDZ8ane4fmsEIcuc8eMKUt55Y2q/fbNzsYu41YTZzzsJUSeqVjT8/iTQtgnNdpo=|dwI+uyvZ1h/iZ03VQ+/wrGEFYVewBUUl/syYgjsNMbE="

// V2 wrapped account state and as the expected user key after V1→V2 reinit.
let TEST_VECTOR_USER_KEY_V2_B64 =
    "pQEEAlCxZkKFDpp70P5mWPmOjf3xAzoAARF5BIQDBAUGIFggCFcd6XLISUfLaITyU9yimrYHacdS5XhBayO2663jdSUB"

let TEST_VECTOR_PRIVATE_KEY_V2 =
    "7.g1gdowE6AAEReQMZARwEULFmQoUOmnvQ/mZY+Y6N/fGhBVgYe16rmgYXX3Orgo6y5U5Z8eb+JHTGfcivWQTR+1rVWtHJhEm8G/AtE78Ud3S8qxZmstUKhC5u9xgPvx2e8Fe8QL80Dv0WoEsy0XEb+5EFd8xDlu7OBuCVv2MaoJ/XzAkbpn9IT1vMCPhvRuaktIWMNrQgJ1jnmqjTGObftA02sHnj938tLRNfilw8ln/PBO2GBZQVzTUYfnc+mBeedGyZAxhSxyUwtFB8h3HC/t9BGtLT/bm83Df8rwTc+rGFL5r+T6vczQ+6hvF6kKpUb37XwgLEDsc+J4UTb+4zHaDcTioOYq6Hki8PrsN9PWL57nkhRMi3fKgfz8GDtY+pjp7D9HYV6OMuveSK9l+h16enJwiFDy6XEx+eth4aHPT5hybnOfTWbkEIhUmPD3K2JKvUUxeL9Z6e1EtSylVitO4Lit485KYaY8VASW4MnAzPOUQVwZ4jowHr5X8g0jVtHiLeUuOwDGcqjO/q6//tkiCwjW/W79jk4eqMtqPbOl0XelYVmM4KZCslPZ+2IYS56g/gl8Q2Oj9UGq7QJCsZvV9rBNa4wS3uC9atoWWRqO2PTWkVTurakkK3Fc9VP2bC1lJaWoWVjYpyJJVZh77ktpD3VrFdrT62+de0iaWUAtAr/1ALToNzoTYu3ihyGb6FZMN//XLTKk8GhZGVCluEDClHnziBxCX7Qg/0HRiU7EjsYGhpFnmG2XkvZQb9Pds8gucTbmbUeVfjXZ/IOLm16G/tdit2VIf80zcsvhgxTYys4Cm12N+62fM3aT5L9lqWvBYOMDksy00/3uLPzWbLFWbKItaC1c+bceGS7UDrLim6Pm/Voo2jXCi6EHpXX2/THrJybRDwqmQi7UVWXR3aPx//q9busEXxRyeu0m4lq2AjhQWhOvfPjpJzNX1hRE9Bu7UKYJhUF6DAsXFFKpob0LoARpcjGLFLcO61yV6He2nQFAa+ULXxhrKbISzqO3Q2xMs2p3jQ4Ctm0T+03w9Y5/Yf1qNKaL6AayA2nf0thYgh+OHNEnnkFwvBnTyB5B32E+/cUy7bb3329Pz7h+ruLo5IhGZM5GiEjF4vOSZmZJZ1t2eR4U7oxX0VTpwFPPBUQ3O7A5C2l0g/pGCFda4QlgR5qRA09kaAd9VBSJbQABGH0zWlXNPAjPQ6M9CxxTv9lM/72RSzTvnJqjQNpWGQjYuTi++EN5QZ37Nmlcw9eSa6X1C97ADndWV46dlFowUUDXiczi+Q0bZmFtpvkRg0TWlicS/cURLIfpG7sGwgqIis5R4haQ+RDB1+4oC0xmncWqy7vMESW6trh+icEL2PybwGPnzdngUqEIw5fG9huX3BmxbJjukSjWWk2CH8AaY2lHRXttzpOhpfP9c1cmrwXXUuHwTFMiKdmdwSqGbgebUP25kB9priXO88Jri3Wb739KRV5M2k6/9AspCwpOqlKN6MZm2vElNI+cXSWMHeX3666p4ALr7Vu7+q7iw4s4cO09MMJWsaiTaZBsVRhdoocsej+091JM/yJ29TVDJEMp2vEiia8HQ4k2bH9W9XCB71cpygRMYTFRDJ3Yjly4MYg7whBQnkeu8IYagCY6UZ60V73qhKRZJKuiV6ZTC+objnMPMmi9Kd05WmYFab8ZDP8s4yhU0WJNXdZGwpX7pnoi0T+g/y94sfZNGs5QuKgNEX"

let TEST_VECTOR_SIGNING_KEY_V2 =
    "7.g1gcowE6AAEReQMYZQRQsWZChQ6ae9D+Zlj5jo398aEFWBj8Gg/gn4tQKWO3nq5e/2p9gkzIrKD829RYT3aEUIDOetEtnFqRuQ3Cz13693WqDnKHM5Buzi6LcTsxo1jphYR7vlE5nYLjCpOCAftPN1oLfs5SCNkwwMENhujpVftfDzciE99aLEJDS9A="

let TEST_VECTOR_SECURITY_STATE_V2 =
    "hFgepAEnAxg8BFAmkP0QgfdMVbIujX55W/yNOgABOH8CoFgkomhlbnRpdHlJZFBHOOw2BI9OQoNq+Vl1xZZKZ3ZlcnNpb24CWEAlchbJR0vmRfShG8On7Q2gknjkw4Dd6MYBLiH4u+/CmfQdmjNZdf6kozgW/6NXyKVNu8dAsKsin+xxXkDyVZoG"

let TEST_VECTOR_SIGNED_PUBLIC_KEY_V2 =
    "hFgepAEnAxg8BFAmkP0QgfdMVbIujX55W/yNOgABOH8BoFkBTqNpYWxnb3JpdGhtAG1jb250ZW50Rm9ybWF0AGlwdWJsaWNLZXlZASYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDP/7WM8nUepxoJ0qtM+azxcly+eZ31qUjjZTZcX/gYw1MzkoXWAjqyeFH/bdktq1lEUwegrxkIxKkY2SMtp0CvPnaV1x5O8E6FBSJbKWRlDg181rfEhgm5tc6aR4PJ827IvFVm9xk6Sj091P5DHZDEOsWLZc2jYjtpUV3X38I4gSR7HiYnR4DcwcWkoJ3FhtxMCwYgPz6RVH0vzhLUmm1mgbzH6IH8Pf9DjLTZSxBikVO7S9s9jzhiZbTeeAl3FbNLxfj9Qkj+NoSfms7jGVTlBwvSXgjJs/ktGkT1cR5QcBMpU4bt41+l73MN8pXapCih9Awf1W+RY7imxpYOMFJ3AgMBAAFYQMq/hT4wod2w8xyoM7D86ctuLNX4ZRo+jRHf2sZfaO7QsvonG/ZYuNKF5fq8wpxMRjfoMvnY2TTShbgzLrW8BA4="

// Captured V2 upgrade-token vectors
let VALID_UPGRADE_TOKEN_WRAPPED_UK1 =
    "7.g1g+owE6AAEReQN4ImFwcGxpY2F0aW9uL3guYml0d2FyZGVuLmxlZ2FjeS1rZXkEULFmQoUOmnvQ/mZY+Y6N/fGhBVgYgUyr3KwZvsXCF5TOQ80u1A0nl5kafCSHWFCr1ENvhJ5W66Iy0AMqrZ9KLlCBNaCSRF7eAXO1aXf71eYE6b836ubAOdF5FS85ohjaySEfav2f52GcT/VarfGQlmXkahLEpyoGB/LWfmj3Nw=="

let VALID_UPGRADE_TOKEN_WRAPPED_UK2 =
    "2.4jPuHAB6HrnQAq2arCkiLQ==|nUAFXUp60v/hAh+qwjq1TqltFGjotkT7NSGhz7/y3bYQRevzvOUZvEUrw/30d7MRWv6nBYYf73dXjIGDtqsf/tzpYcQRHgfyUWtrT+Kv2Ok=|amC94qKYGFGUDUSQMJcTPcHHjMq+pAebNd2eDk8efWM="

let MISMATCHED_UPGRADE_TOKEN_WRAPPED_UK1 =
    "7.g1g+owE6AAEReQN4ImFwcGxpY2F0aW9uL3guYml0d2FyZGVuLmxlZ2FjeS1rZXkEUPDQ2DjDnI14PW23v8b0GQehBVgYncrn0Orw7dOK0mH+VVaSRWz3x6JJFEIiWFD2Ui4TeeENrGC0P9iCvlutrS0wCCpM+gMvAwLkidBeiNOAJ0TV9gXiKSCFCuyu+/Tuw49D/G3vp5cnxS2hbe7Q62ubI1/EGmL8yjgOnuMwSg=="

let MISMATCHED_UPGRADE_TOKEN_WRAPPED_UK2 =
    "2.kMXLlusmgVa3j6HZ9IL02g==|cNAewMA4BsenXjQyawhYwVpgpZHgLhIvNQeoAf6+eA8QbQpzfKYM+sPqQO7JeEMStJfn/6yewPVd+S/lADOnxUElZIUyGZeD1Ifmh2vXMb8=|cwSUXxHoYWGus1U36IuZAYTtxWAK0f8CA7cOYfqlh9k="

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
func makeV1InitializedClient(stateBridge: InMemoryStateBridge) async throws -> Client {
    let client = Client(tokenProvider: MockTokenProvider(), settings: nil)
    client.kmStateBridge().registerBridgeImpl(bridgeImpl: stateBridge)

    let req = InitUserCryptoRequest(
        userId: TEST_VECTOR_USER_ID_V1,
        kdfParams: .pbkdf2(iterations: TEST_VECTOR_KDF_ITERATIONS_V1),
        email: TEST_EMAIL,
        accountCryptographicState: .v1(privateKey: TEST_VECTOR_PRIVATE_KEY_V1),
        method: .masterPasswordUnlock(
            password: TEST_PASSWORD,
            masterPasswordUnlock: MasterPasswordUnlockData(
                kdf: .pbkdf2(iterations: TEST_VECTOR_KDF_ITERATIONS_V1),
                masterKeyWrappedUserKey: TEST_VECTOR_MASTER_KEY_WRAPPED_USER_KEY_V1,
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
        userId: TEST_VECTOR_USER_ID_V1,
        kdfParams: .argon2id(iterations: 6, memory: 32, parallelism: 4),
        email: TEST_EMAIL,
        accountCryptographicState: makeV2AccountCryptographicState(),
        method: .decryptedKey(decryptedUserKey: TEST_VECTOR_USER_KEY_V2_B64),
        upgradeToken: nil
    )

    try await client.crypto().initializeUserCrypto(req: req)
    return client
}

/// V2 wrapped account state from the test vectors. Decrypts only when
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
/// with the V1 user key derived from `makeV1InitializedClient`.
func makeValidUpgradeToken() -> V2UpgradeToken {
    V2UpgradeToken(
        wrappedUserKey1: VALID_UPGRADE_TOKEN_WRAPPED_UK1,
        wrappedUserKey2: VALID_UPGRADE_TOKEN_WRAPPED_UK2
    )
}

/// Structurally valid `V2UpgradeToken` whose wrapped keys are bound to unrelated
/// V1/V2 keys, so unwrapping with the V1 client's user key fails.
/// Useful both for the `InvalidUpgradeToken` test and as a placeholder where
/// reinit is expected to error out before unwrapping.
func makeMockUpgradeToken() -> V2UpgradeToken {
    V2UpgradeToken(
        wrappedUserKey1: MISMATCHED_UPGRADE_TOKEN_WRAPPED_UK1,
        wrappedUserKey2: MISMATCHED_UPGRADE_TOKEN_WRAPPED_UK2
    )
}
