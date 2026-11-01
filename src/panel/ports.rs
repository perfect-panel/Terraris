// SPDX-License-Identifier: GPL-3.0-only

use std::{collections::BTreeMap, net::IpAddr, sync::Arc};

use async_trait::async_trait;

use super::{
    DeviceClaim, Fetch, NodeStatus, OnlineUser, ProtocolName, Result, ServerConfig, SubscriptionId,
    Traffic, User, Validator,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DevicePolicy {
    AtomicPanelLease,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtocolPolicy {
    pub devices: DevicePolicy,
    pub report_active_and_unconfirmed: bool,
    pub max_online_entries: usize,
}

#[async_trait]
pub trait ServerClient: Send + Sync {
    async fn get_config(&self, validator: Option<&Validator>) -> Result<Fetch<ServerConfig>>;
}

#[async_trait]
pub trait ProtocolClient: Send + Sync {
    fn protocol(&self) -> &ProtocolName;
    fn policy(&self) -> ProtocolPolicy;
    async fn get_users(&self, validator: Option<&Validator>) -> Result<Fetch<Vec<User>>>;
    async fn get_alive(&self) -> Result<BTreeMap<SubscriptionId, u64>>;
    async fn claim_device(&self, user: SubscriptionId, source: IpAddr) -> Result<DeviceClaim>;
    async fn report_online(&self, users: &[OnlineUser]) -> Result<()>;
    async fn report_traffic(&self, traffic: &[Traffic]) -> Result<()>;
}

#[async_trait]
pub trait StatusClient: Send + Sync {
    async fn report_status(&self, status: NodeStatus) -> Result<()>;
}

pub trait Connection: Send + Sync {
    fn server(&self) -> Arc<dyn ServerClient>;
    fn protocol(&self, name: &str) -> Result<Arc<dyn ProtocolClient>>;
    fn status(&self, name: &str) -> Result<Arc<dyn StatusClient>>;
}

pub trait Provider: Send + Sync {
    type Options;
    fn open(&self, options: Self::Options) -> Result<Arc<dyn Connection>>;
}
