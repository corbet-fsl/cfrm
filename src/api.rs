use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use ts_rs::TS;

macro_rules! dto {
    ($name:ident { $($field:ident: $kind:ty),* $(,)? }) => {
        #[derive(Clone, Serialize, Deserialize, JsonSchema, TS)]
        #[serde(deny_unknown_fields)]
        pub struct $name { $(pub $field: $kind),* }
    };
}
dto!(ChallengeInput { credential: Vec<u8> });
dto!(Possession { session: Vec<u8>, request_nonce: Vec<u8>, signature: Vec<u8> });
dto!(EnterInput { challenge: Vec<u8>, signature: Vec<u8>, publication: Vec<u8>, record_proof: Vec<u8> });
dto!(ReplaceInput { possession: Possession, expected_revision: Vec<u8>, publication: Vec<u8>, record_proof: Vec<u8> });
dto!(HeartbeatInput { possession: Possession, expected_revision: Vec<u8> });
dto!(DepartInput {
    possession: Possession
});
dto!(SearchInput { possession: Possession, cursor: Option<Vec<u8>>, page_size: u16 });
dto!(WatchInput { possession: Possession, cursor: Vec<u8> });
dto!(CiphertextInput { possession: Possession, owner: Vec<u8>, revision: Vec<u8> });
// The room owner defines the bounded opaque command and permit encoding.
dto!(RoomInput { possession: Possession, command: Vec<u8> });

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Requirement {
    Credential,
    DeviceChallenge,
    CurrentDeviceSession,
}

pub struct ActionInfo {
    pub name: &'static str,
    pub requirement: Requirement,
    pub input_schema: fn() -> Value,
}

macro_rules! actions {
    ($($variant:ident => $name:literal ($input:ty) $authority:ident),* $(,)?) => {
        #[derive(Clone, Serialize, Deserialize, JsonSchema, TS)]
        #[serde(tag = "action", content = "input", deny_unknown_fields)]
        pub enum Request { $(#[serde(rename = $name)] $variant($input)),* }

        impl Request {
            pub fn info(&self) -> ActionInfo {
                match self { $(Self::$variant(_) => ActionInfo {
                    name: $name, requirement: Requirement::$authority,
                    input_schema: || json!(schemars::schema_for!($input)),
                }),* }
            }
        }

        pub fn actions() -> Vec<ActionInfo> {
            vec![$(ActionInfo { name: $name, requirement: Requirement::$authority,
                input_schema: || json!(schemars::schema_for!($input)), }),*]
        }

        /// Each action's transport and authorization metadata come from this
        /// registry. The wire body always includes the version and tagged action.
        pub fn typescript() -> String {
            let cfg = ts_rs::Config::default();
            let mut declarations = std::collections::BTreeSet::new();
            $(declarations.insert(<$input>::decl(&cfg));)*
            declarations.insert(Possession::decl(&cfg));
            declarations.insert(Request::decl(&cfg));
            declarations.insert(Call::decl(&cfg));
            declarations.insert(Failure::decl(&cfg));
            declarations.insert(ErrorCode::decl(&cfg));
            declarations.into_iter().map(|s| format!("export {s}\n")).collect()
        }
    };
}

actions! {
    Challenge => "challenge" (ChallengeInput) Credential,
    Enter => "enter" (EnterInput) DeviceChallenge,
    Replace => "replace" (ReplaceInput) CurrentDeviceSession,
    Heartbeat => "heartbeat" (HeartbeatInput) CurrentDeviceSession,
    Depart => "depart" (DepartInput) CurrentDeviceSession,
    Search => "search" (SearchInput) CurrentDeviceSession,
    Watch => "watch" (WatchInput) CurrentDeviceSession,
    Ciphertext => "ciphertext" (CiphertextInput) CurrentDeviceSession,
    RoomOrder => "room_order" (RoomInput) CurrentDeviceSession,
    RoomRelay => "room_relay" (RoomInput) CurrentDeviceSession,
    RoomResume => "room_resume" (RoomInput) CurrentDeviceSession,
    RoomHandover => "room_handover" (RoomInput) CurrentDeviceSession,
}

dto!(Call {
    version: u16,
    request: Request
});

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidRequest,
    UnsupportedVersion,
    Origin,
    Host,
    Capacity,
    Timeout,
    TooLarge,
    MediaType,
    AuthorityUnavailable,
    Transport,
}
dto!(Failure { error: ErrorCode });

impl Call {
    pub fn new(request: Request) -> Self {
        Self {
            version: 1,
            request,
        }
    }

    pub fn decode(bytes: &[u8], maximum: usize) -> Result<Self, ErrorCode> {
        if bytes.len() > maximum {
            return Err(ErrorCode::TooLarge);
        }
        let call: Self = serde_json::from_slice(bytes).map_err(|_| ErrorCode::InvalidRequest)?;
        if call.version != 1 {
            return Err(ErrorCode::UnsupportedVersion);
        }
        Ok(call)
    }
}

/// This is a refusal, never a replacement admission verifier. The public
/// success surface will be supplied by Gather's verified child capabilities.
pub fn execute(_call: &Call) -> Result<std::convert::Infallible, ErrorCode> {
    Err(ErrorCode::AuthorityUnavailable)
}

pub fn openapi() -> Value {
    let mut paths = serde_json::Map::new();
    for action in actions() {
        paths.insert(format!("/v1/{}", action.name), json!({"post": {
            "operationId": action.name,
            "x-authority": action.requirement,
            "requestBody": {"required":true,"content":{"application/json":{"schema":{
                "allOf":[schema::<Call>(),{"properties":{
                    "version":{"const":1},"request":{"properties":{"action":{"const":action.name}}}
                }}]
            }}}},
            "responses":{"503":{"description":"Required current authority unavailable","content":{"application/json":{"schema":schema::<Failure>()}}}}
        }}));
    }
    json!({"openapi":"3.1.0","info":{"title":"Forum","version":"1"},"paths":paths})
}

fn schema<T: JsonSchema>() -> Value {
    let mut settings = schemars::generate::SchemaSettings::default();
    settings.inline_subschemas = true;
    json!(settings.into_generator().into_root_schema_for::<T>())
}
