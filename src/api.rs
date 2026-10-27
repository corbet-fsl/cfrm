use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use ts_rs::TS;

macro_rules! dto {
    ($name:ident { $($field:ident: $kind:ty),* $(,)? }) => {
        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
        #[serde(deny_unknown_fields)]
        pub struct $name { $(pub $field: $kind),* }
    };
}
dto!(ChallengeInput { publication: Vec<u8> });
dto!(SettingsInput {});
dto!(Possession { session: Vec<u8>, request_nonce: Vec<u8>, signature: Vec<u8> });
dto!(EnterInput { challenge: Vec<u8>, signature: Vec<u8>, publication: Vec<u8>, record_proof: Vec<u8> });
// `accepting_waves`: the device's own reading of the member's Wave budget, a
// findability hint only (the relation's reservation cap still enforces the
// budget). Missing or null means unknown, which keeps the member visible.
dto!(ReplaceInput { possession: Possession, expected_revision: Vec<u8>, publication: Vec<u8>, record_proof: Vec<u8>, accepting_waves: Option<bool> });
dto!(HeartbeatInput { possession: Possession, expected_revision: Vec<u8>, accepting_waves: Option<bool> });
dto!(DepartInput {
    possession: Possession
});
dto!(SearchInput { possession: Possession, cursor: Option<Vec<u8>>, page_size: u16 });
dto!(WatchInput { possession: Possession, cursor: Vec<u8> });
dto!(CiphertextInput { possession: Possession, owner: Vec<u8>, revision: Vec<u8> });
// The room owner defines the bounded opaque command and permit encoding.
dto!(RoomEpochInput {
    possession: Possession
});
dto!(RoomIssueInput { possession: Possession, operation: Vec<u8>, blinded_request: Vec<u8> });
dto!(RoomListInput { possession: Possession, cursor: Option<Vec<u8>>, page_size: u16 });
dto!(RoomEpochOutput { incarnation: String, epoch: Vec<u8> });
dto!(RoomIssueOutput { signature: Vec<u8> });
dto!(RoomInput { room_pass: Vec<u8>, command: Vec<u8> });

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Requirement {
    PublishedPolicy,
    Credential,
    DeviceChallenge,
    CurrentDeviceSession,
    AnonymousRoomPass,
}

pub struct ActionInfo {
    pub name: &'static str,
    pub requirement: Requirement,
    pub input_schema: fn() -> Value,
}

macro_rules! actions {
    ($($variant:ident => $name:literal ($input:ty => $output:ty) $authority:ident),* $(,)?) => {
        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
        #[serde(tag = "action", content = "input", deny_unknown_fields)]
        pub enum Request { $(#[serde(rename = $name)] $variant($input)),* }

        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
        #[serde(tag = "action", content = "output", deny_unknown_fields)]
        pub enum Output { $(#[serde(rename = $name)] $variant($output)),* }
        impl Output {
            pub fn action(&self) -> &'static str { match self { $(Self::$variant(_) => $name),* } }
        }

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
            $(declarations.insert(<$input>::decl(&cfg)); declarations.insert(<$output>::decl(&cfg));)*
            declarations.insert(Output::decl(&cfg));
            declarations.insert(Reply::decl(&cfg));
            declarations.insert(PublicationOutput::decl(&cfg));
            declarations.insert(ListedRoom::decl(&cfg));
            declarations.insert(Possession::decl(&cfg));
            declarations.insert(Request::decl(&cfg));
            declarations.insert(Call::decl(&cfg));
            declarations.insert(Failure::decl(&cfg));
            declarations.insert(ErrorCode::decl(&cfg));
            declarations.into_iter().map(|s| format!("export {s}\n")).collect()
        }
    };
}

dto!(ChallengeOutput { challenge: Vec<u8> });
dto!(SettingsOutput { heartbeat_ms: u64, lease_ms: u64, minimum_client_version: String, room_passes_per_epoch: u64, revision: u64, policy_epoch: u64, valid_until: u64, publication: Vec<u8> });
dto!(EnterOutput { session: Vec<u8>, revision: Vec<u8>, expires_at_ms: u64 });
dto!(LiveOutput { revision: Vec<u8>, expires_at_ms: u64 });
dto!(EmptyOutput {});
dto!(PublicationOutput { owner: Vec<u8>, revision: u64, publication: Vec<u8> });
dto!(ListedRoom { room: Vec<u8>, name: String, description: String, here_now: u32 });
dto!(RoomListOutput { rooms: Vec<ListedRoom>, cursor: Option<Vec<u8>> });
dto!(SearchOutput { requester_revision: Vec<u8>, entries: Vec<PublicationOutput>, cursor: Option<Vec<u8>>, watch: Vec<u8> });
dto!(WatchOutput { requester_revision: Vec<u8>, upserts: Vec<PublicationOutput>, removed: Vec<Vec<u8>>, cursor: Option<Vec<u8>>, watch: Vec<u8> });
dto!(CiphertextOutput { ciphertext: Vec<u8> });
dto!(RoomOutput { result: Vec<u8> });
/// The signed request body version. 2 added `accepting_waves` to heartbeat and
/// replace; every other version is refused. Replies stay at version 1.
pub const CALL_VERSION: u16 = 2;
dto!(Reply {
    version: u16,
    response: Output
});

impl Reply {
    pub fn new(response: Output) -> Self {
        Self {
            version: 1,
            response,
        }
    }
}

actions! {
    Settings => "settings" (SettingsInput => SettingsOutput) PublishedPolicy,
    Challenge => "challenge" (ChallengeInput => ChallengeOutput) Credential,
    Enter => "enter" (EnterInput => EnterOutput) DeviceChallenge,
    Replace => "replace" (ReplaceInput => LiveOutput) CurrentDeviceSession,
    Heartbeat => "heartbeat" (HeartbeatInput => LiveOutput) CurrentDeviceSession,
    Depart => "depart" (DepartInput => EmptyOutput) CurrentDeviceSession,
    Search => "search" (SearchInput => SearchOutput) CurrentDeviceSession,
    Watch => "watch" (WatchInput => WatchOutput) CurrentDeviceSession,
    Ciphertext => "ciphertext" (CiphertextInput => CiphertextOutput) CurrentDeviceSession,
    RoomEpoch => "room_epoch" (RoomEpochInput => RoomEpochOutput) CurrentDeviceSession,
    RoomIssue => "room_issue" (RoomIssueInput => RoomIssueOutput) CurrentDeviceSession,
    RoomList => "room_list" (RoomListInput => RoomListOutput) CurrentDeviceSession,
    RoomConnect => "room_connect" (RoomInput => RoomOutput) AnonymousRoomPass,
    RoomRenew => "room_renew" (RoomInput => RoomOutput) AnonymousRoomPass,
    RoomDisconnect => "room_disconnect" (RoomInput => RoomOutput) AnonymousRoomPass,
    RoomRead => "room_read" (RoomInput => RoomOutput) AnonymousRoomPass,
    RoomOrder => "room_order" (RoomInput => RoomOutput) AnonymousRoomPass,
    RoomRelay => "room_relay" (RoomInput => RoomOutput) AnonymousRoomPass,
    RoomResume => "room_resume" (RoomInput => RoomOutput) AnonymousRoomPass,
    RoomPublish => "room_publish" (RoomInput => RoomOutput) AnonymousRoomPass,
    RoomHandover => "room_handover" (RoomInput => RoomOutput) AnonymousRoomPass,
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
    Rejected,
    ResetRequired,
    Transport,
    Reconcile,
}
dto!(Failure { error: ErrorCode });

impl Call {
    pub fn new(request: Request) -> Self {
        Self {
            version: CALL_VERSION,
            request,
        }
    }

    pub fn decode(bytes: &[u8], maximum: usize) -> Result<Self, ErrorCode> {
        if bytes.len() > maximum {
            return Err(ErrorCode::TooLarge);
        }
        let call: Self = serde_json::from_slice(bytes).map_err(|_| ErrorCode::InvalidRequest)?;
        if call.version != CALL_VERSION {
            return Err(ErrorCode::UnsupportedVersion);
        }
        Ok(call)
    }
}

/// This is a refusal, never a replacement admission verifier. The public
/// success surface will be supplied by Gather's verified child capabilities.
pub fn execute(_call: &Call) -> Result<Reply, ErrorCode> {
    Err(ErrorCode::AuthorityUnavailable)
}

pub fn openapi() -> Value {
    let mut paths = serde_json::Map::new();
    for action in actions() {
        paths.insert(format!("/v1/{}", action.name), json!({"post": {
            "operationId": action.name,
            "x-authority": action.requirement,
            "requestBody": {"required":true,"content":{"application/json":{"schema":request_schema(action.name)}}},
            "responses":{"200":{"description":"Current owner-authorized response","content":{"application/json":{"schema":reply_schema(action.name)}}},"503":{"description":"Required current authority unavailable","content":{"application/json":{"schema":schema::<Failure>()}}}}
        }}));
    }
    json!({"openapi":"3.1.0","info":{"title":"Forum","version":"1"},"paths":paths})
}

fn schema<T: JsonSchema>() -> Value {
    let mut settings = schemars::generate::SchemaSettings::default();
    settings.inline_subschemas = true;
    json!(settings.into_generator().into_root_schema_for::<T>())
}

/// MCP projection of the same versioned action registry. Transport hosts must
/// preserve original arguments for execute_tool and enforce their session class.
pub fn mcp_tools() -> Value {
    json!({"tools": actions().into_iter().map(|action| json!({
        "name":action.name,
        "description":format!("Forum {}", action.name),
        "inputSchema":request_schema(action.name),
        "outputSchema":{"type":"object","oneOf":[reply_schema(action.name),schema::<Failure>()]},
        "_meta":{"cfrm/authority":action.requirement}
    })).collect::<Vec<_>>()})
}

/// Arguments are original JSON bytes, not a pre-decoded map that lost duplicate
/// fields. Missing current authority refuses exactly as the HTTP/Rust path does.
pub fn execute_tool(name: &str, arguments: &[u8], maximum: usize) -> Result<Reply, ErrorCode> {
    let call = Call::decode(arguments, maximum)?;
    if call.request.info().name != name {
        return Err(ErrorCode::InvalidRequest);
    }
    execute(&call)
}

fn request_schema(name: &str) -> Value {
    json!({"type":"object","allOf":[schema::<Call>(),{"properties":{
        "version":{"const":CALL_VERSION},"request":{"properties":{"action":{"const":name}}}
    }}]})
}

impl Request {
    pub fn possession(&self) -> Option<&Possession> {
        match self {
            Self::Replace(v) => Some(&v.possession),
            Self::Heartbeat(v) => Some(&v.possession),
            Self::Depart(v) => Some(&v.possession),
            Self::Search(v) => Some(&v.possession),
            Self::Watch(v) => Some(&v.possession),
            Self::Ciphertext(v) => Some(&v.possession),
            Self::RoomEpoch(v) => Some(&v.possession),
            Self::RoomIssue(v) => Some(&v.possession),
            Self::RoomList(v) => Some(&v.possession),
            _ => None,
        }
    }
    pub fn possession_mut(&mut self) -> Option<&mut Possession> {
        match self {
            Self::Replace(v) => Some(&mut v.possession),
            Self::Heartbeat(v) => Some(&mut v.possession),
            Self::Depart(v) => Some(&mut v.possession),
            Self::Search(v) => Some(&mut v.possession),
            Self::Watch(v) => Some(&mut v.possession),
            Self::Ciphertext(v) => Some(&mut v.possession),
            Self::RoomEpoch(v) => Some(&mut v.possession),
            Self::RoomIssue(v) => Some(&mut v.possession),
            Self::RoomList(v) => Some(&mut v.possession),
            _ => None,
        }
    }
    /// One registry-owned canonical transcript; only the signature is omitted.
    /// Session, nonce, action, version and every operation parameter remain.
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>, ErrorCode> {
        let mut request = self.clone();
        let possession = request.possession_mut().ok_or(ErrorCode::InvalidRequest)?;
        possession.signature.clear();
        serde_json::to_vec(&Call::new(request)).map_err(|_| ErrorCode::InvalidRequest)
    }
}

fn reply_schema(name: &str) -> Value {
    json!({"type":"object","allOf":[schema::<Reply>(),{"properties":{
        "version":{"const":1},"response":{"properties":{"action":{"const":name}}}
    }}]})
}
