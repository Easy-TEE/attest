//! A mock PCS server used for testing
use std::{
    collections::HashMap as StdHashMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::{
    Json,
    Router,
    extract::{Query, State},
    response::IntoResponse,
    routing::get,
};
use dcap_qvl::QuoteCollateralV3;
use rcgen::{
    BasicConstraints,
    CertificateParams,
    CertificateRevocationListParams,
    IsCa,
    Issuer,
    KeyPair,
    KeyUsagePurpose,
    SerialNumber,
};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use tokio::{net::TcpListener, task::JoinHandle};

#[derive(Clone)]
pub(super) struct MockPcsConfig {
    pub(super) fmspc: String,
    pub(super) include_fmspcs_listing: bool,
    pub(super) tcb_next_update: String,
    pub(super) qe_next_update: String,
    pub(super) refreshed_tcb_next_update: Option<String>,
    pub(super) refreshed_qe_next_update: Option<String>,
}

/// A mock PCS server so we can run tests without using the Intel PCS.
pub(super) struct MockPcsServer {
    pub(super) base_url: String,
    _task: JoinHandle<()>,
    tcb_calls: Arc<AtomicUsize>,
    qe_calls: Arc<AtomicUsize>,
}

impl Drop for MockPcsServer {
    fn drop(&mut self) {
        self._task.abort();
    }
}

impl MockPcsServer {
    pub(super) fn tcb_call_count(&self) -> usize {
        self.tcb_calls.load(Ordering::SeqCst)
    }

    pub(super) fn qe_call_count(&self) -> usize {
        self.qe_calls.load(Ordering::SeqCst)
    }
}

#[derive(Clone)]
struct MockPcsState {
    fmspc: String,
    include_fmspcs_listing: bool,
    base_tcb_info: Value,
    base_qe_identity: Value,
    tcb_signature_hex: String,
    qe_signature_hex: String,
    tcb_next_update: String,
    qe_next_update: String,
    refreshed_tcb_next_update: Option<String>,
    refreshed_qe_next_update: Option<String>,
    pck_crl: Vec<u8>,
    pck_crl_issuer_chain: String,
    tcb_issuer_chain: String,
    qe_issuer_chain: String,
    root_ca_crl_hex: String,
    tcb_calls: Arc<AtomicUsize>,
    qe_calls: Arc<AtomicUsize>,
}

pub(super) async fn spawn_mock_pcs_server(config: MockPcsConfig) -> MockPcsServer {
    let base_collateral: QuoteCollateralV3 =
        serde_saphyr::from_slice(include_bytes!("test-assets/dcap-quote-collateral-00.yaml"))
            .unwrap();
    let now = OffsetDateTime::now_utc();
    let fresh_crl = generate_mock_crl_der(now, now + Duration::days(365));

    let mut tcb_info: Value = serde_json::from_str(&base_collateral.tcb_info).unwrap();
    tcb_info["nextUpdate"] = Value::String(config.tcb_next_update.clone());

    let mut qe_identity: Value = serde_json::from_str(&base_collateral.qe_identity).unwrap();
    qe_identity["nextUpdate"] = Value::String(config.qe_next_update.clone());

    let tcb_calls = Arc::new(AtomicUsize::new(0));
    let qe_calls = Arc::new(AtomicUsize::new(0));
    let state = Arc::new(MockPcsState {
        fmspc: config.fmspc,
        include_fmspcs_listing: config.include_fmspcs_listing,
        base_tcb_info: tcb_info,
        base_qe_identity: qe_identity,
        tcb_signature_hex: hex::encode(&base_collateral.tcb_info_signature),
        qe_signature_hex: hex::encode(&base_collateral.qe_identity_signature),
        tcb_next_update: config.tcb_next_update,
        qe_next_update: config.qe_next_update,
        refreshed_tcb_next_update: config.refreshed_tcb_next_update,
        refreshed_qe_next_update: config.refreshed_qe_next_update,
        pck_crl: fresh_crl.clone(),
        pck_crl_issuer_chain: "mock-pck-crl-issuer-chain".to_string(),
        tcb_issuer_chain: "mock-tcb-info-issuer-chain".to_string(),
        qe_issuer_chain: "mock-qe-issuer-chain".to_string(),
        root_ca_crl_hex: hex::encode(fresh_crl),
        tcb_calls: tcb_calls.clone(),
        qe_calls: qe_calls.clone(),
    });

    let app = Router::new()
        .route("/sgx/certification/v4/fmspcs", get(mock_fmspcs_handler))
        .route("/sgx/certification/v4/pckcrl", get(mock_pck_crl_handler))
        .route("/tdx/certification/v4/tcb", get(mock_tcb_handler))
        .route("/tdx/certification/v4/qe/identity", get(mock_qe_identity_handler))
        .route("/sgx/certification/v4/rootcacrl", get(mock_root_ca_crl_handler))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    MockPcsServer { base_url: format!("http://{addr}"), _task: task, tcb_calls, qe_calls }
}

async fn mock_pck_crl_handler(
    State(state): State<Arc<MockPcsState>>,
    Query(params): Query<StdHashMap<String, String>>,
) -> impl IntoResponse {
    assert!(
        matches!(params.get("ca").map(String::as_str), Some("processor") | Some("platform")),
        "unexpected ca query value for pckcrl"
    );
    assert_eq!(params.get("encoding"), Some(&"der".to_string()));
    ([("SGX-PCK-CRL-Issuer-Chain", state.pck_crl_issuer_chain.clone())], state.pck_crl.clone())
}

async fn mock_fmspcs_handler(State(state): State<Arc<MockPcsState>>) -> impl IntoResponse {
    if state.include_fmspcs_listing {
        Json(json!([{
            "fmspc": state.fmspc,
            "platform": "all",
        }]))
    } else {
        Json(json!([]))
    }
}

async fn mock_tcb_handler(
    State(state): State<Arc<MockPcsState>>,
    Query(params): Query<StdHashMap<String, String>>,
) -> impl IntoResponse {
    assert_eq!(params.get("fmspc"), Some(&state.fmspc));
    let call_number = state.tcb_calls.fetch_add(1, Ordering::SeqCst) + 1;
    let mut tcb_info = state.base_tcb_info.clone();
    let next_update = if call_number == 1 {
        state.tcb_next_update.clone()
    } else {
        state.refreshed_tcb_next_update.clone().unwrap_or_else(|| state.tcb_next_update.clone())
    };
    tcb_info["nextUpdate"] = Value::String(next_update);
    (
        [("SGX-TCB-Info-Issuer-Chain", state.tcb_issuer_chain.clone())],
        Json(json!({
            "tcbInfo": tcb_info,
            "signature": state.tcb_signature_hex,
        })),
    )
}

async fn mock_qe_identity_handler(
    State(state): State<Arc<MockPcsState>>,
    Query(params): Query<StdHashMap<String, String>>,
) -> impl IntoResponse {
    assert_eq!(params.get("update"), Some(&"standard".to_string()));
    let call_number = state.qe_calls.fetch_add(1, Ordering::SeqCst) + 1;
    let mut qe_identity = state.base_qe_identity.clone();
    let next_update = if call_number == 1 {
        state.qe_next_update.clone()
    } else {
        state.refreshed_qe_next_update.clone().unwrap_or_else(|| state.qe_next_update.clone())
    };
    qe_identity["nextUpdate"] = Value::String(next_update);
    (
        [("SGX-Enclave-Identity-Issuer-Chain", state.qe_issuer_chain.clone())],
        Json(json!({
            "enclaveIdentity": qe_identity,
            "signature": state.qe_signature_hex,
        })),
    )
}

async fn mock_root_ca_crl_handler(State(state): State<Arc<MockPcsState>>) -> impl IntoResponse {
    state.root_ca_crl_hex.clone()
}

/// Create a mock certificate revocation list
fn generate_mock_crl_der(this_update: OffsetDateTime, next_update: OffsetDateTime) -> Vec<u8> {
    let mut issuer_params = CertificateParams::new(Vec::new()).unwrap();
    issuer_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    issuer_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::CrlSign,
    ];
    let issuer_key = KeyPair::generate().unwrap();
    let issuer = Issuer::new(issuer_params, issuer_key);

    CertificateRevocationListParams {
        this_update,
        next_update,
        crl_number: SerialNumber::from(1_u64),
        issuing_distribution_point: None,
        revoked_certs: Vec::new(),
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    }
    .signed_by(&issuer)
    .unwrap()
    .der()
    .to_vec()
}
