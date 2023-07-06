use super::{ClaimData, ClaimsMap, CCA_SW_COMP_TITLE};
use crate::{TokenError, token_c::bindgen::{CCA_PLAT_CHALLENGE, CCA_PLAT_VERIFICATION_SERVICE, CCA_PLAT_PROFILE, CCA_PLAT_INSTANCE_ID, CCA_PLAT_IMPLEMENTATION_ID, CCA_PLAT_SECURITY_LIFECYCLE, CCA_PLAT_CONFIGURATION, CCA_PLAT_HASH_ALGO_ID, CCA_SW_COMP_HASH_ALGORITHM, CCA_SW_COMP_MEASUREMENT_VALUE, CCA_SW_COMP_VERSION, CCA_SW_COMP_SIGNER_ID}};

pub struct PlatClaims {
    pub challenge: Vec<u8>,
    pub verification_service: String,
    pub profile: String,
    pub instance_id: Vec<u8>,
    pub implementation_id: Vec<u8>,
    pub lifecycle: i64,
    pub configuration: Vec<u8>,
    pub hash_algo: String
}

impl PlatClaims {
    fn get_claim(key: u32, claims: &ClaimsMap) -> Result<ClaimData, TokenError> {
        if claims.contains_key(&key) {
            Ok(claims[&key].data.clone())
        } else {
            Err(TokenError::MissingPlatClaim(key))
        }
    }

    pub fn from_raw_claims(claims: &ClaimsMap) -> Result<Self, TokenError> {
        Ok(Self {
            challenge: Self::get_claim(CCA_PLAT_CHALLENGE, claims)?.try_into()?,
            verification_service: Self::get_claim(CCA_PLAT_VERIFICATION_SERVICE, claims)?.try_into()?,
            profile: Self::get_claim(CCA_PLAT_PROFILE, claims)?.try_into()?,
            instance_id: Self::get_claim(CCA_PLAT_INSTANCE_ID, claims)?.try_into()?,
            implementation_id: Self::get_claim(CCA_PLAT_IMPLEMENTATION_ID, claims)?.try_into()?,
            lifecycle: Self::get_claim(CCA_PLAT_SECURITY_LIFECYCLE, claims)?.try_into()?,
            configuration: Self::get_claim(CCA_PLAT_CONFIGURATION, claims)?.try_into()?,
            hash_algo: Self::get_claim(CCA_PLAT_HASH_ALGO_ID, claims)?.try_into()?
        })
    }
}

pub struct PlatSwComponent {
    pub ty: String,
    pub hash_algo: String,
    pub value: Vec<u8>,
    pub version: String,
    pub signer_id: Vec<u8>
}

impl PlatSwComponent {
    fn get_claim(key: u32, claims: &ClaimsMap) -> Result<ClaimData, TokenError> {
        if claims.contains_key(&key) {
            Ok(claims[&key].data.clone())
        } else {
            Err(TokenError::MissingPlatSwClaim(key))
        }
    }

    pub fn from_raw_claims(claims: &ClaimsMap, plat_hash_algo: &String) -> Result<Self, TokenError> {
        Ok(Self {
            ty: Self::get_claim(CCA_SW_COMP_TITLE, claims)?.try_into()?,
            hash_algo: match Self::get_claim(CCA_SW_COMP_HASH_ALGORITHM, claims) {
                Ok(i) => i.try_into()?,
                Err(_) => plat_hash_algo.clone()
            },
            value: Self::get_claim(CCA_SW_COMP_MEASUREMENT_VALUE, claims)?.try_into()?,
            version: Self::get_claim(CCA_SW_COMP_VERSION, claims)?.try_into()?,
            signer_id: Self::get_claim(CCA_SW_COMP_SIGNER_ID, claims)?.try_into()?,
        })
    }
}
