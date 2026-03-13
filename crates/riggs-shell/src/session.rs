use chrono::{DateTime, Utc};
use riggs_types::errors::RiggsError;
use uuid::Uuid;
use crate::auth::ShellAuth;

pub struct ShellSession {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub user: String,
    _auth: ShellAuth,
}

impl ShellSession {
    pub fn new(auth: ShellAuth) -> Result<Self, RiggsError> {
        Ok(Self {
            id: Uuid::now_v7(),
            created_at: Utc::now(),
            user: String::from("unknown"),
            _auth: auth,
        })
    }

    pub async fn start(&self) -> Result<(), RiggsError> {
        todo!()
    }

    pub async fn stop(&self) -> Result<(), RiggsError> {
        todo!()
    }
}
