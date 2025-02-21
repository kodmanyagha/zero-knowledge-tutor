use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use num_bigint::BigUint;
use parking_lot::Mutex;
use tonic::{Code, Response, Status};
use zkp_chaum_pedersen::{ZkpConstants, ZKP};

use crate::zkp_auth::{
    auth_server::Auth, AuthenticationAnswerRequest, AuthenticationAnswerResponse,
    AuthenticationChallengeRequest, AuthenticationChallengeResponse, RegisterRequest,
    RegisterResponse,
};

#[derive(Debug, Default)]
pub struct AuthImpl {
    pub user_info: Arc<Mutex<HashMap<String, UserInfo>>>,
    pub auth_id_to_user: Arc<Mutex<HashMap<String, String>>>,
}

#[derive(Debug, Default)]
pub struct UserInfo {
    // registration
    pub user_name: String,
    pub y1: BigUint,
    pub y2: BigUint,

    // authorization
    pub r1: BigUint,
    pub r2: BigUint,

    // verification
    pub c: BigUint,
    pub s: BigUint,
    pub session_id: String,
}

#[tonic::async_trait]
impl Auth for AuthImpl {
    async fn register(
        &self,
        request: tonic::Request<RegisterRequest>,
    ) -> std::result::Result<tonic::Response<RegisterResponse>, tonic::Status> {
        log::info!("Processing register request: {:?}", request);

        let RegisterRequest { name, y1, y2 } = request.into_inner();

        let y1 = BigUint::from_bytes_be(&y1);
        let y2 = BigUint::from_bytes_be(&y2);

        let mut user_info = UserInfo::default();
        user_info.user_name = name.clone();
        user_info.y1 = y1;
        user_info.y2 = y2;

        let mut user_info_map = &mut self.user_info.lock();
        user_info_map.insert(name, user_info);

        Ok(Response::new(RegisterResponse {}))
    }

    async fn create_authentication_challenge(
        &self,
        request: tonic::Request<AuthenticationChallengeRequest>,
    ) -> std::result::Result<tonic::Response<AuthenticationChallengeResponse>, tonic::Status> {
        log::info!("Processing create_authentication_challenge: {:?}", request);
        let request = request.into_inner();
        let mut user_info_map = &mut self.user_info.lock();

        if let Some(user_info) = user_info_map.get_mut(&request.user) {
            user_info.r1 = BigUint::from_bytes_be(&request.r1);
            user_info.r2 = BigUint::from_bytes_be(&request.r2);

            let zkp_constants = ZkpConstants::new();

            let c = ZKP::generate_random_below(&zkp_constants.q);
            let auth_id = ZKP::generate_random_string(12);

            let mut auth_id_to_user = &mut self.auth_id_to_user.lock();
            auth_id_to_user.insert(auth_id.clone(), request.user.clone());

            Ok(Response::new(AuthenticationChallengeResponse {
                auth_id,
                c: c.to_bytes_be(),
            }))
        } else {
            Err(Status::new(
                Code::NotFound,
                format!("User: {} not found.", request.user),
            ))
        }
    }

    async fn verify_authentication(
        &self,
        request: tonic::Request<AuthenticationAnswerRequest>,
    ) -> std::result::Result<tonic::Response<AuthenticationAnswerResponse>, tonic::Status> {
        log::info!("Processing verify_authentication: {:?}", request);
        let request = request.into_inner();
        let mut auth_id_to_user_map = &mut self.auth_id_to_user.lock();

        if let Some(user_name) = auth_id_to_user_map.get_mut(&request.auth_id) {
            let mut user_info = self.user_info.lock();
            let user_info = user_info.get_mut(user_name);

            let Some(user_info) = user_info else {
                return Err(Status::new(
                    Code::NotFound,
                    format!("Auth ID: {} not found.", request.auth_id),
                ));
            };

            let zkp = ZKP::default();
            let verification = zkp.verify(
                &user_info.r1,
                &user_info.r2,
                &user_info.y1,
                &user_info.y2,
                &user_info.c,
                &user_info.s,
            );

            let session_id = ZKP::generate_random_string(12);

            Ok(Response::new(AuthenticationAnswerResponse { session_id }))
        } else {
            Err(Status::new(
                Code::NotFound,
                format!("Auth ID: {} not found.", request.auth_id),
            ))
        }
    }
}
