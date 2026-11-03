//! Key slot ids, test vectors, and helpers shared by the tests of this crate.

use bitwarden_crypto::{EncString, KeyStoreContext, SymmetricCryptoKey, key_slot_ids};
use bitwarden_encoding::B64;

use crate::organization_private_key::OrganizationPrivateKey;

key_slot_ids! {
    #[symmetric]
    pub enum TestSymmKey {
        Organization,
        #[local]
        Local(LocalId),
    }

    #[private]
    pub enum TestPrivateKey {
        Organization,
        #[local]
        Local(LocalId),
    }

    #[signing]
    pub enum TestSigningKey {
        Organization,
        #[local]
        Local(LocalId),
    }

    pub TestIds => TestSymmKey, TestPrivateKey, TestSigningKey;
}

pub(crate) const TEST_VECTOR_V1_ORG_KEY: &str =
    "KGP9Nc2/91w+42Z9VzY0m7h18avuZcq4ICM8Rhdc3BD92LbWS2TQkVBzavvUM684WKXiC22NJi2EwaiDW4YTAA==";
/// The organization private key, wrapped with [`TEST_VECTOR_V1_ORG_KEY`].
pub(crate) const TEST_VECTOR_V1_WRAPPED_PRIVATE_KEY: &str = "2.bi9TWF/zrujUg1y+v8ECtQ==|kEMkuRt42j65YZnPEc4bLOT0/WDZwWSNJNGlUMdr/LRF3qi/vCnZ7eT0+7MruTccmyoAjKmsXdoBcufrOdPBUguFQn1LQMGqHqCyyB3SIijOlLyOOmxWYqoLUjihy8o8URGWjrAGWZnkeYWHTlFZP09Fag2xCwiQ/qS32Q+qTGGHDs0FiwjplcPkW9knlmgCXbuyPqDnEYoa0Qs/CC1hUCzFFrWs7QkE+5eLaNHxuBPpsrY6y795kEu9ve38F3piY9b6lQpc/iPGv8Zfh1isI7Mpy1zMwntXGSHjUOy17nPxCqkgYufuNGnwGNwsGjkLAl7e7bD39SYfEpTDaRUgmTl8UrZDx274e6Um1LLvokf3HiL1tboJ9/TW8IiMuAdrb3PLTH6Sep8lqZ3WhNADfMMJle9kCojHp6XSB14in1JqP0636exYeJu+FhUC1TfrthuQN2QDQ8LAvgZR7YvzkTJX3Sc5jP7m/yCmCbHhIqIAaGqJsRwAee0EMsKcALz3/akVoyjHU2LHD3dzQnyMyszyRNYViBNYAM9qBN2DqwWRDOtM171xNVJcTFsAh4mBSLiLOlDsXqLqHVKu2VJNE1XhTQ5Szubqefa/Or7nfxXcxDvivqZ7d5NfDFEskUMqh5yq1KoLK0oK5c+KvY/COIZr/kct+qtfZsXo3w5xJnPOqrAKGm+9CF4OINpLM8Z3csdZf9l5XjlmO1kIuBbquQZ0EZCHzD/GEfXRGB8BEkugdTfpnTDtmmuAJXkIY6t6e6pRUU9u4/sl+U7Iuh22fOA59SuQOElr5Lxre+hQBrRfJS3tSMEtMjYhVmltrngH+SLRxMxH/evbe2uvNaaxlFJe6EK1vqchyTX6nM8Z+2Yjb5pOAzrKQYqwwmVys9IHfjXhybqv10gFpDXBE/eq8u9xs9LbQQ03EbveQUtqdh/ms8SxLOQA9Sm9JwHEL0Zni+8NdAa5orDYzOi53bQLgrs+uUldgB/KOW2goTnKGm4YTbMAXEbum8pST8EXB9jNDXyofyN8IQUoLRvVkEgzbSPBS1sYpkkKdLZy3ojOCKnMnHXIVtzJojFckiutbj6d927X5w51E/RDMoAdylGRVKnmqLKysFRqL+pZK8Cyo+ECr7notG8kr7pVnofzigjKZS9qkRmqEa9bju1GgI20g4cxro8/0O0XnU1o0Mx46qH3niORY59i5bdMwaDS6H2c6+rmf9bIFwwgyAZvHlVdcGNoBGPR3ZXHThwI1OmWSslLWVW0IaS4utB1jL4zvHPCqh/ButA8HeRmU/NYSfaqb9YXyzn+C7ED15MWXkYmZzeE38HHxhqs12+oj+WFcg4d5/e2UcccuVi36SWhA0xWk8Kk2D6e1Pz1lmaw20vpb0eUq4AS5ZnMmWTEiKORFeGNTIROq9vuPuitLrREedu9PGjf5aeKcNqlq2nr7fOaxyi2ocKs7pLqVBUH1G7zHpCo3Rt1+o18guXFHT56vQFfkzoUNXiS6TRM4Mkl3s0TyGgBhxZkNJleTI6y4xhfH1iathBnLcfelLbxZhDB1wh3RXowS32jpM/J4pSUuNEmSLSqRQtRJY41BG00nYY02qEbakkgk6pS6a0/CWphyLfHAzUWbabOhqR1iPN9/ZiecjI=|eoklmBw+LYy2NNwjLOuA4+szKH5SzLGPlrhIJ/vfmW4=";
pub(crate) const TEST_VECTOR_V1_MEMBER_USER_KEY: &str =
    "fyH9aTPp220BPFLasxV7e6Adbt20lJ/BFA2w/JddEVsuHn1oDjKKE8YT8u9L5RMiZuD39Ya//b78HoA1LJv/5w==";

pub(crate) fn add_symmetric_key(key: &str, ctx: &mut KeyStoreContext<'_, TestIds>) -> TestSymmKey {
    ctx.add_local_symmetric_key(SymmetricCryptoKey::try_from(B64::try_from(key).unwrap()).unwrap())
}

/// Loads [`TEST_VECTOR_V1_ORG_KEY`] into the `Organization` slot and returns
/// [`TEST_VECTOR_V1_WRAPPED_PRIVATE_KEY`].
pub(crate) fn load_v1_test_vectors(ctx: &mut KeyStoreContext<'_, TestIds>) -> EncString {
    let org_key = add_symmetric_key(TEST_VECTOR_V1_ORG_KEY, ctx);
    ctx.persist_symmetric_key(org_key, TestSymmKey::Organization)
        .unwrap();
    TEST_VECTOR_V1_WRAPPED_PRIVATE_KEY.parse().unwrap()
}

pub(crate) fn unwrap_v1_organization_private_key(
    ctx: &mut KeyStoreContext<'_, TestIds>,
) -> OrganizationPrivateKey<TestIds> {
    let wrapped_private_key = load_v1_test_vectors(ctx);
    OrganizationPrivateKey::unwrap_with_organization_key(
        TestSymmKey::Organization,
        &wrapped_private_key,
        ctx,
    )
    .unwrap()
}
