use std::collections::HashMap;
use std::fmt::Debug;

use async_trait::async_trait;
use futures::sink::{Sink, SinkExt};
use futures::stream;
use rand;

use super::{ClientInfo, PgWireConnectionState, METADATA_DATABASE, METADATA_USER};
use crate::error::{PgWireError, PgWireResult};
use crate::messages::response::{ReadyForQuery, READY_STATUS_IDLE};
use crate::messages::startup::{Authentication, BackendKeyData, ParameterStatus, Startup};
use crate::messages::{PgWireBackendMessage, PgWireFrontendMessage};

/// Handles startup process and frontend messages  抽象出有关处理握手阶段请求的handler
#[async_trait]
pub trait StartupHandler: Send + Sync {
    /// A generic frontend message callback during startup phase.
    async fn on_startup<C>(
        &self,
        client: &mut C,
        message: PgWireFrontendMessage,
    ) -> PgWireResult<()>
    where
        C: ClientInfo + Sink<PgWireBackendMessage> + Unpin + Send,
        C::Error: Debug,
        PgWireError: From<<C as Sink<PgWireBackendMessage>>::Error>;
}

// 描述一个可以提供服务端配置的对象
pub trait ServerParameterProvider: Send + Sync {
    fn server_parameters<C>(&self, _client: &C) -> Option<HashMap<String, String>>
    where
        C: ClientInfo;
}

/// Default noop parameter provider.
///
/// This provider responds frontend with default parameters:
///
/// - `DateStyle: ISO YMD`: the default text serialization in this library is
/// using `YMD` style date. If you override this, or use your own serialization
/// for date types, remember to update this as well.
/// - `server_encoding: UTF8`
/// - `client_encoding: UTF8`
/// - `integer_datetimes: on`:
///
#[derive(Debug, Getters, Setters)]
#[getset(get = "pub", set = "pub")]
pub struct DefaultServerParameterProvider {
    server_version: String,
    server_encoding: String,
    client_encoding: String,
    date_style: String,
    integer_datetimes: String,
}

impl Default for DefaultServerParameterProvider {
    fn default() -> Self {
        Self {
            server_version: env!("CARGO_PKG_VERSION").to_owned(),
            server_encoding: "UTF8".to_owned(),
            client_encoding: "UTF8".to_owned(),
            date_style: "ISO YMD".to_owned(),
            integer_datetimes: "on".to_owned(),
        }
    }
}

impl ServerParameterProvider for DefaultServerParameterProvider {

    // 生成一个新对象 而不消耗内部字段所有权
    fn server_parameters<C>(&self, _client: &C) -> Option<HashMap<String, String>>
    where
        C: ClientInfo,
    {
        let mut params = HashMap::with_capacity(5);
        params.insert("server_version".to_owned(), self.server_version.clone());
        params.insert("server_encoding".to_owned(), self.server_encoding.clone());
        params.insert("client_encoding".to_owned(), self.client_encoding.clone());
        params.insert("DateStyle".to_owned(), self.date_style.clone());
        params.insert(
            "integer_datetimes".to_owned(),
            self.integer_datetimes.clone(),
        );

        Some(params)
    }
}

#[derive(Debug, new, Getters, Clone)]
#[getset(get = "pub")]
pub struct Password {
    salt: Option<Vec<u8>>,
    password: Vec<u8>,
}

// 本次登录使用的用户名/主机/选择的数据库名
#[derive(Debug, new, Getters)]
#[getset(get = "pub")]
pub struct LoginInfo<'a> {
    user: Option<&'a String>,
    database: Option<&'a String>,
    host: String,
}

impl<'a> LoginInfo<'a> {
    // 默认从client信息中获取
    pub fn from_client_info<C>(client: &'a C) -> LoginInfo
    where
        C: ClientInfo,
    {
        LoginInfo {
            user: client.metadata().get(METADATA_USER),
            database: client.metadata().get(METADATA_DATABASE),
            host: client.socket_addr().ip().to_string(),
        }
    }
}

/// Represents auth source, the source returns password either in cleartext or
/// hashed with salt.
///
/// When using with different authentication mechanism, the developer can choose
/// specific implementation of `AuthSource`. For example, with cleartext
/// authentication, salt is not required, while in md5pass, a 4-byte salt is
/// needed.
/// 从内置数据源加载password
#[async_trait]
pub trait AuthSource: Send + Sync {
    /// Get password from the `AuthSource`.
    ///
    /// `Password` has a an optional salt field when it's hashed.
    async fn get_password(&self, login: &LoginInfo) -> PgWireResult<Password>;
}

/// 将startUp阶段获得的信息补充到元数据中
pub fn save_startup_parameters_to_metadata<C>(client: &mut C, startup_message: &Startup)
where
    C: ClientInfo + Sink<PgWireBackendMessage> + Unpin + Send,
    C::Error: Debug,
{
    client.metadata_mut().extend(
        startup_message
            .parameters()
            .iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned())),
    );
}

/// 代表认证结束
pub async fn finish_authentication<C, P>(client: &mut C, server_parameter_provider: &P)
where
    C: ClientInfo + Sink<PgWireBackendMessage> + Unpin + Send,
    C::Error: Debug,
    P: ServerParameterProvider,
{
    let mut messages = vec![PgWireBackendMessage::Authentication(Authentication::Ok)];

    if let Some(parameters) = server_parameter_provider.server_parameters(client) {
        for (k, v) in parameters {
            messages.push(PgWireBackendMessage::ParameterStatus(ParameterStatus::new(
                k, v,
            )));
        }
    }

    // TODO: store this backend key
    messages.push(PgWireBackendMessage::BackendKeyData(BackendKeyData::new(
        std::process::id() as i32,
        rand::random::<i32>(),
    )));
    // 返回一个准备就绪的消息 代表client可以发起查询请求了
    messages.push(PgWireBackendMessage::ReadyForQuery(ReadyForQuery::new(
        READY_STATUS_IDLE,
    )));
    let mut message_stream = stream::iter(messages.into_iter().map(Ok));
    client.send_all(&mut message_stream).await.unwrap();
    client.set_state(PgWireConnectionState::ReadyForQuery);
}

pub mod cleartext;
pub mod md5pass;
pub mod noop;
pub mod scram;
