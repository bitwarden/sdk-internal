// V2 (XAES-256-GCM user key) test account fixtures.
//
// Mirrors the `test_bitwarden_com_account_v2` fixture in
// `crates/bitwarden-core/src/client/test_accounts.rs`. All values belong together — the private key,
// signing key and security state are all bound to the user key below — so they must be copied over
// as a set.
//
// The default account in `utils.ts` is a V1 account whose user key is `Aes256CbcHmac`, an algorithm
// that carries no key id. Anything testing key-id behaviour needs this account instead.

import { EncString, Kdf, SignedPublicKey, SignedSecurityState } from "@bitwarden/sdk-internal";

const encstring = (s: string) => s as unknown as EncString;

// `test_bitwarden_com_account_v2` uses Argon2id, unlike the PBKDF2 accounts elsewhere.
export const V2_KDF_PARAMS: Kdf = {
  argon2id: { iterations: 6, memory: 32, parallelism: 4 },
};

export const V2_PRIVATE_KEY = encstring(
  "7.g1gdowE6AAEReQMZARwEULFmQoUOmnvQ/mZY+Y6N/fGhBVgYe16rmgYXX3Orgo6y5U5Z8eb+JHTGfcivWQTR+1rVWtHJhEm8G/AtE78Ud3S8qxZmstUKhC5u9xgPvx2e8Fe8QL80Dv0WoEsy0XEb+5EFd8xDlu7OBuCVv2MaoJ/XzAkbpn9IT1vMCPhvRuaktIWMNrQgJ1jnmqjTGObftA02sHnj938tLRNfilw8ln/PBO2GBZQVzTUYfnc+mBeedGyZAxhSxyUwtFB8h3HC/t9BGtLT/bm83Df8rwTc+rGFL5r+T6vczQ+6hvF6kKpUb37XwgLEDsc+J4UTb+4zHaDcTioOYq6Hki8PrsN9PWL57nkhRMi3fKgfz8GDtY+pjp7D9HYV6OMuveSK9l+h16enJwiFDy6XEx+eth4aHPT5hybnOfTWbkEIhUmPD3K2JKvUUxeL9Z6e1EtSylVitO4Lit485KYaY8VASW4MnAzPOUQVwZ4jowHr5X8g0jVtHiLeUuOwDGcqjO/q6//tkiCwjW/W79jk4eqMtqPbOl0XelYVmM4KZCslPZ+2IYS56g/gl8Q2Oj9UGq7QJCsZvV9rBNa4wS3uC9atoWWRqO2PTWkVTurakkK3Fc9VP2bC1lJaWoWVjYpyJJVZh77ktpD3VrFdrT62+de0iaWUAtAr/1ALToNzoTYu3ihyGb6FZMN//XLTKk8GhZGVCluEDClHnziBxCX7Qg/0HRiU7EjsYGhpFnmG2XkvZQb9Pds8gucTbmbUeVfjXZ/IOLm16G/tdit2VIf80zcsvhgxTYys4Cm12N+62fM3aT5L9lqWvBYOMDksy00/3uLPzWbLFWbKItaC1c+bceGS7UDrLim6Pm/Voo2jXCi6EHpXX2/THrJybRDwqmQi7UVWXR3aPx//q9busEXxRyeu0m4lq2AjhQWhOvfPjpJzNX1hRE9Bu7UKYJhUF6DAsXFFKpob0LoARpcjGLFLcO61yV6He2nQFAa+ULXxhrKbISzqO3Q2xMs2p3jQ4Ctm0T+03w9Y5/Yf1qNKaL6AayA2nf0thYgh+OHNEnnkFwvBnTyB5B32E+/cUy7bb3329Pz7h+ruLo5IhGZM5GiEjF4vOSZmZJZ1t2eR4U7oxX0VTpwFPPBUQ3O7A5C2l0g/pGCFda4QlgR5qRA09kaAd9VBSJbQABGH0zWlXNPAjPQ6M9CxxTv9lM/72RSzTvnJqjQNpWGQjYuTi++EN5QZ37Nmlcw9eSa6X1C97ADndWV46dlFowUUDXiczi+Q0bZmFtpvkRg0TWlicS/cURLIfpG7sGwgqIis5R4haQ+RDB1+4oC0xmncWqy7vMESW6trh+icEL2PybwGPnzdngUqEIw5fG9huX3BmxbJjukSjWWk2CH8AaY2lHRXttzpOhpfP9c1cmrwXXUuHwTFMiKdmdwSqGbgebUP25kB9priXO88Jri3Wb739KRV5M2k6/9AspCwpOqlKN6MZm2vElNI+cXSWMHeX3666p4ALr7Vu7+q7iw4s4cO09MMJWsaiTaZBsVRhdoocsej+091JM/yJ29TVDJEMp2vEiia8HQ4k2bH9W9XCB71cpygRMYTFRDJ3Yjly4MYg7whBQnkeu8IYagCY6UZ60V73qhKRZJKuiV6ZTC+objnMPMmi9Kd05WmYFab8ZDP8s4yhU0WJNXdZGwpX7pnoi0T+g/y94sfZNGs5QuKgNEX",
);

export const V2_SIGNING_KEY = encstring(
  "7.g1gcowE6AAEReQMYZQRQsWZChQ6ae9D+Zlj5jo398aEFWBj8Gg/gn4tQKWO3nq5e/2p9gkzIrKD829RYT3aEUIDOetEtnFqRuQ3Cz13693WqDnKHM5Buzi6LcTsxo1jphYR7vlE5nYLjCpOCAftPN1oLfs5SCNkwwMENhujpVftfDzciE99aLEJDS9A=",
);

export const V2_SECURITY_STATE =
  "hFgepAEnAxg8BFAmkP0QgfdMVbIujX55W/yNOgABOH8CoFgkomhlbnRpdHlJZFBHOOw2BI9OQoNq+Vl1xZZKZ3ZlcnNpb24CWEAlchbJR0vmRfShG8On7Q2gknjkw4Dd6MYBLiH4u+/CmfQdmjNZdf6kozgW/6NXyKVNu8dAsKsin+xxXkDyVZoG" as SignedSecurityState;

export const V2_SIGNED_PUBLIC_KEY =
  "hFgepAEnAxg8BFAmkP0QgfdMVbIujX55W/yNOgABOH8BoFkBTqNpYWxnb3JpdGhtAG1jb250ZW50Rm9ybWF0AGlwdWJsaWNLZXlZASYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDP/7WM8nUepxoJ0qtM+azxcly+eZ31qUjjZTZcX/gYw1MzkoXWAjqyeFH/bdktq1lEUwegrxkIxKkY2SMtp0CvPnaV1x5O8E6FBSJbKWRlDg181rfEhgm5tc6aR4PJ827IvFVm9xk6Sj091P5DHZDEOsWLZc2jYjtpUV3X38I4gSR7HiYnR4DcwcWkoJ3FhtxMCwYgPz6RVH0vzhLUmm1mgbzH6IH8Pf9DjLTZSxBikVO7S9s9jzhiZbTeeAl3FbNLxfj9Qkj+NoSfms7jGVTlBwvSXgjJs/ktGkT1cR5QcBMpU4bt41+l73MN8pXapCih9Awf1W+RY7imxpYOMFJ3AgMBAAFYQMq/hT4wod2w8xyoM7D86ctuLNX4ZRo+jRHf2sZfaO7QsvonG/ZYuNKF5fq8wpxMRjfoMvnY2TTShbgzLrW8BA4=" as unknown as SignedPublicKey;

/** The account's user key, COSE-encoded and base64'd. Unlocks the account directly. */
export const V2_DECRYPTED_USER_KEY =
  "pQEEAlCxZkKFDpp70P5mWPmOjf3xAzoAARF5BIQDBAUGIFggCFcd6XLISUfLaITyU9yimrYHacdS5XhBayO2663jdSUB";

/**
 * The key id carried by `V2_DECRYPTED_USER_KEY`. The COSE key decodes to
 * `a5 01 04 02 50 <16 bytes> ...` — CBOR label `2` (`kid`) holding exactly these bytes. This is the
 * value the SDK reports when it backfills the user key id to the server.
 */
export const V2_USER_KEY_ID = "b16642850e9a7bd0fe6658f98e8dfdf1";
