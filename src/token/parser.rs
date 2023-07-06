use super::{Claim, ClaimData};
use crate::TokenError;

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
    fn get_claim(title: &'static str, claims: &[Claim]) -> Result<ClaimData, TokenError> {
        claims.iter().find(|i| i.present && i.title == title)
            .map_or(Err(TokenError::MissingPlatClaim(title)), |i| Ok(i.data.clone()))
    }

    pub fn from_raw_claims(claims: &[Claim]) -> Result<Self, TokenError> {
        Ok(Self {
            challenge: Self::get_claim("Challange", claims)?.try_into()?,
            verification_service: Self::get_claim("Verification service", claims)?.try_into()?,
            profile: Self::get_claim("Profile", claims)?.try_into()?,
            instance_id: Self::get_claim("Instance ID", claims)?.try_into()?,
            implementation_id: Self::get_claim("Implementation ID", claims)?.try_into()?,
            lifecycle: Self::get_claim("Lifecycle", claims)?.try_into()?,
            configuration: Self::get_claim("Configuration", claims)?.try_into()?,
            hash_algo: Self::get_claim("Platform hash algo", claims)?.try_into()?
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
    fn get_claim(title: &'static str, claims: &[Claim]) -> Result<ClaimData, TokenError> {
        claims.iter().find(|i| i.present && i.title == title)
            .map_or(Err(TokenError::MissingPlatSwClaim(title)), |i| Ok(i.data.clone()))
    }

    pub fn from_raw_claims(claims: &[Claim], plat_hash_algo: &String) -> Result<Self, TokenError> {
        Ok(Self {
            ty: Self::get_claim("SW Type", claims)?.try_into()?,
            hash_algo: match Self::get_claim("Hash algorithm", claims) {
                Ok(i) => i.try_into()?,
                Err(_) => plat_hash_algo.clone()
            },
            value: Self::get_claim("Measurement value", claims)?.try_into()?,
            version: Self::get_claim("Version", claims)?.try_into()?,
            signer_id: Self::get_claim("Signer ID", claims)?.try_into()?,
        })
    }
}
