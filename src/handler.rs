use solana_sdk::{commitment_config::CommitmentConfig, native_token::LAMPORTS_PER_SOL, pubkey};
use serde_json::json;
use axum::{response::IntoResponse, Json, extract::Query, http::StatusCode};
use serde::Deserialize;
use bs58;
use spl_token::{instruction::initialize_mint2, ID as TOKEN_PROGRAM_ID};
use base64::{engine::general_purpose, Engine as _};
use std::str::FromStr;
use spl_token::solana_program::pubkey::Pubkey;
use spl_token::{instruction::mint_to};
use solana_sdk::signature::Signature;
use solana_sdk::{signature::Keypair, signer::Signer};
use std::convert::TryInto;
use spl_associated_token_account::get_associated_token_address;
use spl_token::instruction::transfer as spl_transfer;
use tracing::{info};

macro_rules! respond {
    ($status:expr, $body:expr, $func_name:expr) => {{
        let body_val = $body;
        info!(target: $func_name, "outgoing response => status: {:?}, body: {}", $status, body_val);
        ($status, Json(body_val))
    }};
}

pub async fn hello_world_handler() -> &'static str {
    info!("hello_world_handler incoming request");
    let response: &'static str = "Hello World";
    info!("hello_world_handler outgoing response: {}", response);
    response
}


#[derive(Deserialize, Debug)]
pub struct GenerateRequest {
    valid: Option<bool>,
}

pub async fn generate_keypair_handler(Query(params): Query<GenerateRequest>) -> impl IntoResponse {
    info!("generate_keypair_handler incoming: {:?}", params);

    let is_valid = params.valid.unwrap_or(true);

    if !is_valid {
        return respond!(
            StatusCode::BAD_REQUEST,
            json!({
                "success": false,
                "error": "invalid request, 'valid' flag set to false"
            }),
            "generate_keypair_handler"
        );
    }

    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();

    respond!(
        StatusCode::OK,
        json!({
            "success": true,
            "data": {
                "pubkey": pubkey,
                "secret": secret
            }
        }),
        "generate_keypair_handler"
    )
}

#[derive(Deserialize, Debug)]
pub struct TokenCreateRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: Option<String>,
    mint: Option<String>,
    decimals: u8,
}

pub async fn create_token_handler(Json(req): Json<TokenCreateRequest>) -> impl IntoResponse {
    info!("create_token_handler incoming: {:?}", req);

    let validation_error = match (&req.mint, &req.mint_authority) {
        (None, _) => Some("Missing required field: mint"),
        (_, None) => Some("Missing required field: mintAuthority"),
        (Some(m), Some(a)) if m.trim().is_empty() => Some("mint cannot be empty"),
        (Some(m), Some(a)) if a.trim().is_empty() => Some("mintAuthority cannot be empty"),
       
        (Some(m), _) if !m.chars().all(|c| c.is_ascii_alphanumeric()) => {
            Some("mint must be a valid base58 string")
        }
        (_, Some(a)) if !a.chars().all(|c| c.is_ascii_alphanumeric()) => {
            Some("mintAuthority must be a valid base58 string")
        }
        
        (Some(m), _) if m.len() != 44 && m.len() != 45 => {
            Some("mint must be 32 bytes (encoded as ~44 characters in base58)")
        }
        
        (_, Some(a)) if a.len() != 44 && a.len() != 45 => {
            Some("mintAuthority must be 32 bytes (encoded as ~44 characters in base58)")
        }
        _ => None,
    };

    if let Some(error_msg) = validation_error {
        return respond!(
            StatusCode::BAD_REQUEST,
            json!({
                "success": false,
                "error": error_msg
            }),
            "create_token_handler"
        );
    }

    
    if req.decimals > 18 {
        return respond!(
            StatusCode::BAD_REQUEST,
            json!({
                "success": false,
                "error": "decimals cannot exceed 18"
            }),
            "create_token_handler"
        );
    }

    
    let mint_str = req.mint.unwrap();
    let authority_str = req.mint_authority.unwrap();

   
    let mint_pubkey = match Pubkey::from_str(&mint_str) {
        Ok(pk) => pk,
        Err(err) => {
            return respond!(
                StatusCode::BAD_REQUEST,
                json!({
                    "success": false,
                    "error": format!("invalid mint public key: {}", err)
                }),
                "create_token_handler"
            );
        }
    };

    
    let authority_pubkey = match Pubkey::from_str(&authority_str) {
        Ok(pk) => pk,
        Err(err) => {
            return respond!(
                StatusCode::BAD_REQUEST,
                json!({
                    "success": false,
                    "error": format!("invalid mintAuthority public key: {}", err)
                }),
                "create_token_handler"
            );
        }
    };

    
    if mint_pubkey == authority_pubkey {
        return respond!(
            StatusCode::BAD_REQUEST,
            json!({
                "success": false,
                "error": "mint and mintAuthority cannot be the same address"
            }),
            "create_token_handler"
        );
    }

    
    let instruction = match initialize_mint2(
        &TOKEN_PROGRAM_ID,
        &mint_pubkey,
        &authority_pubkey,
        Some(&authority_pubkey),
        req.decimals,
    ) {
        Ok(ix) => ix,
        Err(err) => {
            return respond!(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({
                    "success": false,
                    "error": format!("failed to build instruction: {}", err)
                }),
                "create_token_handler"
            );
        }
    };

    let accounts_json: Vec<_> = instruction
        .accounts
        .iter()
        .map(|meta| {
            json!({
                "pubkey": meta.pubkey.to_string(),
                "is_signer": meta.is_signer,
                "is_writable": meta.is_writable
            })
        })
        .collect();

    let instruction_data_b64 = general_purpose::STANDARD.encode(&instruction.data);

    respond!(
        StatusCode::OK,
        json!({
            "success": true,
            "data": {
                "program_id": instruction.program_id.to_string(),
                "accounts": accounts_json,
                "instruction_data": instruction_data_b64,
                "details": {
                    "decimals": req.decimals,
                    "mint_address": mint_pubkey.to_string(),
                    "mint_authority": authority_pubkey.to_string(),
                    "freeze_authority": authority_pubkey.to_string()
                }
            }
        }),
        "create_token_handler"
    )
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TokenMintRequest {
    mint: Option<String>,
    destination: Option<String>,
    authority: Option<String>,
    amount: Option<u64>,
}

pub async fn mint_token_handler(Json(req): Json<TokenMintRequest>) -> impl IntoResponse {
    info!("mint_token_handler incoming: {:?}", req);

    // Validate all required fields are present and not empty
    let validation_error = match (&req.mint, &req.destination, &req.authority, &req.amount) {
        (None, _, _, _) => Some("Missing required field: mint"),
        (_, None, _, _) => Some("Missing required field: destination"),
        (_, _, None, _) => Some("Missing required field: authority"),
        (_, _, _, None) => Some("Missing required field: amount"),
        (Some(m), Some(d), Some(a), Some(amt)) if m.trim().is_empty() => Some("mint cannot be empty"),
        (Some(m), Some(d), Some(a), Some(amt)) if d.trim().is_empty() => Some("destination cannot be empty"),
        (Some(m), Some(d), Some(a), Some(amt)) if a.trim().is_empty() => Some("authority cannot be empty"),
        (Some(m), Some(d), Some(a), Some(amt)) if *amt == 0 => Some("amount must be greater than 0"),
        _ => None,
    };

    if let Some(error_msg) = validation_error {
        return respond!(
            StatusCode::BAD_REQUEST,
            json!({
                "success": false,
                "error": error_msg
            }),
            "mint_token_handler"
        );
    }

    // Since we've validated above, we can safely unwrap these
    let mint_str = req.mint.unwrap();
    let destination_str = req.destination.unwrap();
    let authority_str = req.authority.unwrap();
    let amount = req.amount.unwrap();

    // Validate public keys
    let mint_pubkey = match Pubkey::from_str(&mint_str) {
        Ok(pk) => pk,
        Err(_) => {
            return respond!(
                StatusCode::BAD_REQUEST,
                json!({
                    "success": false,
                    "error": "invalid 'mint' public key"
                }),
                "mint_token_handler"
            );
        }
    };

    let dest_pubkey = match Pubkey::from_str(&destination_str) {
        Ok(pk) => pk,
        Err(_) => {
            return respond!(
                StatusCode::BAD_REQUEST,
                json!({
                    "success": false,
                    "error": "invalid 'destination' public key"
                }),
                "mint_token_handler"
            );
        }
    };

    let auth_pubkey = match Pubkey::from_str(&authority_str) {
        Ok(pk) => pk,
        Err(_) => {
            return respond!(
                StatusCode::BAD_REQUEST,
                json!({
                    "success": false,
                    "error": "invalid 'authority' public key"
                }),
                "mint_token_handler"
            );
        }
    };

    // Build instruction
    let instruction = match mint_to(
        &TOKEN_PROGRAM_ID,
        &mint_pubkey,
        &dest_pubkey,
        &auth_pubkey,
        &[],
        amount,
    ) {
        Ok(ix) => ix,
        Err(err) => {
            return respond!(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({
                    "success": false,
                    "error": format!("failed to build instruction: {}", err)
                }),
                "mint_token_handler"
            );
        }
    };

    let accounts_json: Vec<_> = instruction
        .accounts
        .iter()
        .map(|meta| {
            json!({
                "pubkey": meta.pubkey.to_string(),
                "is_signer": meta.is_signer,
                "is_writable": meta.is_writable
            })
        })
        .collect();

    let instruction_data_b64 = general_purpose::STANDARD.encode(instruction.data);

    respond!(
        StatusCode::OK,
        json!({
            "success": true,
            "data": {
                "program_id": instruction.program_id.to_string(),
                "accounts": accounts_json,
                "instruction_data": instruction_data_b64
            }
        }),
        "mint_token_handler"
    )
}

#[derive(Deserialize, Debug)]
pub struct SignMessageRequest {
    message: Option<String>,
    secret: Option<String>,
}

pub async fn sign_message_handler(Json(req): Json<SignMessageRequest>) -> impl IntoResponse {
    info!("sign_message_handler incoming: {:?}", req);

    // Validate all required fields are present and not empty
    let validation_error = match (&req.message, &req.secret) {
        (None, _) => Some("Missing required field: message"),
        (_, None) => Some("Missing required field: secret"),
        (Some(m), Some(s)) if m.trim().is_empty() => Some("message cannot be empty"),
        (Some(m), Some(s)) if s.trim().is_empty() => Some("secret cannot be empty"),
        _ => None,
    };

    if let Some(error_msg) = validation_error {
        return respond!(
            StatusCode::BAD_REQUEST,
            json!({
                "success": false,
                "error": error_msg
            }),
            "sign_message_handler"
        );
    }

    // Since we've validated above, we can safely unwrap these
    let message = req.message.unwrap();
    let secret = req.secret.unwrap();

    // Decode the supplied base58 secret key into raw bytes
    let secret_bytes = match bs58::decode(&secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            return respond!(
                StatusCode::BAD_REQUEST,
                json!({
                    "success": false,
                    "error": "invalid base58-encoded secret key"
                }),
                "sign_message_handler"
            );
        }
    };

    if secret_bytes.len() != 64 {
        return respond!(
            StatusCode::BAD_REQUEST,
            json!({
                "success": false,
                "error": "secret key must decode to 64 bytes"
            }),
            "sign_message_handler"
        );
    }

    // Convert the Vec<u8> into the fixed-size array expected by Keypair::from_bytes
    let secret_array: [u8; 64] = match secret_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            return respond!(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({
                    "success": false,
                    "error": "failed to convert secret key to byte array"
                }),
                "sign_message_handler"
            );
        }
    };

    // Build the Keypair from the secret key bytes
    let keypair = match Keypair::from_bytes(&secret_array) {
        Ok(kp) => kp,
        Err(_) => {
            return respond!(
                StatusCode::BAD_REQUEST,
                json!({
                    "success": false,
                    "error": "provided secret key is invalid"
                }),
                "sign_message_handler"
            );
        }
    };

    // Sign the provided message
    let signature = keypair.sign_message(message.as_bytes());

    // Encode signature in base64 as requested
    let signature_b64 = general_purpose::STANDARD.encode(signature.as_ref());

    respond!(
        StatusCode::OK,
        json!({
            "success": true,
            "data": {
                "signature": signature_b64,
                "public_key": keypair.pubkey().to_string(),
                "message": message
            }
        }),
        "sign_message_handler"
    )
}

#[derive(Deserialize, Debug)]
pub struct VerifyMessageRequest {
    message: Option<String>,
    signature: Option<String>,
    pubkey: Option<String>,
}

pub async fn verify_message_handler(Json(req): Json<VerifyMessageRequest>) -> impl IntoResponse {
    info!("verify_message_handler incoming: {:?}", req);

    // Validate all required fields are present and not empty
    let validation_error = match (&req.message, &req.signature, &req.pubkey) {
        (None, _, _) => Some("Missing required field: message"),
        (_, None, _) => Some("Missing required field: signature"),
        (_, _, None) => Some("Missing required field: pubkey"),
        (Some(m), Some(s), Some(p)) if m.trim().is_empty() => Some("message cannot be empty"),
        (Some(m), Some(s), Some(p)) if s.trim().is_empty() => Some("signature cannot be empty"),
        (Some(m), Some(s), Some(p)) if p.trim().is_empty() => Some("pubkey cannot be empty"),
        _ => None,
    };

    if let Some(error_msg) = validation_error {
        return respond!(
            StatusCode::BAD_REQUEST,
            json!({
                "success": false,
                "error": error_msg
            }),
            "verify_message_handler"
        );
    }

    // Since we've validated above, we can safely unwrap these
    let message = req.message.unwrap();
    let signature_b64 = req.signature.unwrap();
    let pubkey_str = req.pubkey.unwrap();

    // Decode signature from base64
    let sig_bytes = match general_purpose::STANDARD.decode(signature_b64.as_bytes()) {
        Ok(bytes) => bytes,
        Err(_) => {
            return respond!(
                StatusCode::BAD_REQUEST,
                json!({
                    "success": false,
                    "error": "Invalid base64-encoded signature"
                }),
                "verify_message_handler"
            );
        }
    };

    if sig_bytes.len() != 64 {
        return respond!(
            StatusCode::BAD_REQUEST,
            json!({
                "success": false,
                "error": "Signature must be 64 bytes"
            }),
            "verify_message_handler"
        );
    }

    let sig_array: [u8; 64] = match sig_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            return respond!(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({
                    "success": false,
                    "error": "Failed to convert signature bytes"
                }),
                "verify_message_handler"
            );
        }
    };

    let signature = Signature::from(sig_array);

    // Parse pubkey
    let pubkey = match Pubkey::from_str(&pubkey_str) {
        Ok(pk) => pk,
        Err(_) => {
            return respond!(
                StatusCode::BAD_REQUEST,
                json!({
                    "success": false,
                    "error": "Invalid public key"
                }),
                "verify_message_handler"
            );
        }
    };

    let is_valid_signature = signature.verify(&pubkey.to_bytes(), message.as_bytes());

    respond!(
        StatusCode::OK,
        json!({
            "success": true,
            "data": {
                "valid": is_valid_signature,
                "message": message,
                "pubkey": pubkey_str
            }
        }),
        "verify_message_handler"
    )
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SolTransferRequest {
    from: Option<String>,
    to: Option<String>,
    lamports: Option<u64>,
}

pub async fn send_sol_handler(Json(req): Json<SolTransferRequest>) -> impl IntoResponse {
    info!("send_sol_handler incoming: {:?}", req);

    // Validate all required fields are present and not empty
    let validation_error = match (&req.from, &req.to, &req.lamports) {
        (None, _, _) => Some("Missing required field: from"),
        (_, None, _) => Some("Missing required field: to"),
        (_, _, None) => Some("Missing required field: lamports"),
        (Some(f), Some(t), Some(l)) if f.trim().is_empty() => Some("from address cannot be empty"),
        (Some(f), Some(t), Some(l)) if t.trim().is_empty() => Some("to address cannot be empty"),
        (Some(f), Some(t), Some(l)) if *l == 0 => Some("lamports must be greater than 0"),
        _ => None,
    };

    if let Some(error_msg) = validation_error {
        return respond!(
            StatusCode::BAD_REQUEST,
            json!({
                "success": false,
                "error": error_msg
            }),
            "send_sol_handler"
        );
    }

    // Since we've validated above, we can safely unwrap these
    let from_str = req.from.unwrap();
    let to_str = req.to.unwrap();
    let lamports = req.lamports.unwrap();

    // Parse pubkeys
    let from_pubkey = match Pubkey::from_str(&from_str) {
        Ok(pk) => pk,
        Err(_) => {
            return respond!(
                StatusCode::BAD_REQUEST,
                json!({
                    "success": false,
                    "error": "invalid 'from' public key"
                }),
                "send_sol_handler"
            );
        }
    };

    let to_pubkey = match Pubkey::from_str(&to_str) {
        Ok(pk) => pk,
        Err(_) => {
            return respond!(
                StatusCode::BAD_REQUEST,
                json!({
                    "success": false,
                    "error": "invalid 'to' public key"
                }),
                "send_sol_handler"
            );
        }
    };

    // Build transfer instruction
    let instruction = solana_sdk::system_instruction::transfer(&from_pubkey, &to_pubkey, lamports);

    // Extract accounts list (only pubkeys as strings)
    let accounts_json: Vec<_> = instruction
        .accounts
        .iter()
        .map(|meta| meta.pubkey.to_string())
        .collect();

    let instruction_data_b64 = general_purpose::STANDARD.encode(instruction.data);

    respond!(
        StatusCode::OK,
        json!({
            "success": true,
            "data": {
                "program_id": instruction.program_id.to_string(),
                "accounts": accounts_json,
                "instruction_data": instruction_data_b64
            }
        }),
        "send_sol_handler"
    )
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TokenTransferRequest {
    destination: Option<String>,
    mint: Option<String>,
    owner: Option<String>,
    amount: Option<u64>,
}

pub async fn transfer_token_handler(Json(req): Json<TokenTransferRequest>) -> impl IntoResponse {
    info!("transfer_token_handler incoming: {:?}", req);

    // Validate all required fields are present and not empty
    let validation_error = match (&req.destination, &req.mint, &req.owner, &req.amount) {
        (None, _, _, _) => Some("Missing required field: destination"),
        (_, None, _, _) => Some("Missing required field: mint"),
        (_, _, None, _) => Some("Missing required field: owner"),
        (_, _, _, None) => Some("Missing required field: amount"),
        (Some(d), Some(m), Some(o), Some(a)) if d.trim().is_empty() => Some("destination cannot be empty"),
        (Some(d), Some(m), Some(o), Some(a)) if m.trim().is_empty() => Some("mint cannot be empty"),
        (Some(d), Some(m), Some(o), Some(a)) if o.trim().is_empty() => Some("owner cannot be empty"),
        (Some(d), Some(m), Some(o), Some(a)) if *a == 0 => Some("amount must be greater than 0"),
        _ => None,
    };

    if let Some(error_msg) = validation_error {
        return respond!(
            StatusCode::BAD_REQUEST,
            json!({
                "success": false,
                "error": error_msg
            }),
            "transfer_token_handler"
        );
    }

    // Since we've validated above, we can safely unwrap these
    let destination_str = req.destination.unwrap();
    let mint_str = req.mint.unwrap();
    let owner_str = req.owner.unwrap();
    let amount = req.amount.unwrap();

    // Parse pubkeys
    let mint_pubkey = match Pubkey::from_str(&mint_str) {
        Ok(pk) => pk,
        Err(_) => {
            return respond!(
                StatusCode::BAD_REQUEST,
                json!({
                    "success": false,
                    "error": "invalid 'mint' public key"
                }),
                "transfer_token_handler"
            );
        }
    };

    let destination_wallet_pubkey = match Pubkey::from_str(&destination_str) {
        Ok(pk) => pk,
        Err(_) => {
            return respond!(
                StatusCode::BAD_REQUEST,
                json!({
                    "success": false,
                    "error": "invalid 'destination' public key"
                }),
                "transfer_token_handler"
            );
        }
    };

    let owner_wallet_pubkey = match Pubkey::from_str(&owner_str) {
        Ok(pk) => pk,
        Err(_) => {
            return respond!(
                StatusCode::BAD_REQUEST,
                json!({
                    "success": false,
                    "error": "invalid 'owner' public key"
                }),
                "transfer_token_handler"
            );
        }
    };

    // Derive associated token accounts (ATAs)
    let owner_token_account = get_associated_token_address(&owner_wallet_pubkey, &mint_pubkey);
    let destination_token_account =
        get_associated_token_address(&destination_wallet_pubkey, &mint_pubkey);

    // Build transfer instruction (unchecked)
    let instruction = match spl_transfer(
        &TOKEN_PROGRAM_ID,
        &owner_token_account,
        &destination_token_account,
        &owner_wallet_pubkey,
        &[],
        amount,
    ) {
        Ok(ix) => ix,
        Err(err) => {
            return respond!(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({
                    "success": false,
                    "error": format!("failed to build instruction: {}", err)
                }),
                "transfer_token_handler"
            );
        }
    };

    let accounts_json: Vec<_> = instruction
        .accounts
        .iter()
        .map(|meta| {
            json!({
                "pubkey": meta.pubkey.to_string(),
                "is_signer": meta.is_signer,
                "is_writable": meta.is_writable
            })
        })
        .collect();

    let instruction_data_b64 = general_purpose::STANDARD.encode(instruction.data);

    respond!(
        StatusCode::OK,
        json!({
            "success": true,
            "data": {
                "program_id": instruction.program_id.to_string(),
                "accounts": accounts_json,
                "instruction_data": instruction_data_b64
            }
        }),
        "transfer_token_handler"
    )
}

