use payment_watch::core::{
    check_payment, match_payment, ExpectedPayment, ObservedPayment, PaymentWatchArgs, Pubkey,
    RpcClient, WatchError, PARAMETERS_SCHEMA,
};

const RECIPIENT: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const REFERENCE: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";

fn args() -> PaymentWatchArgs {
    PaymentWatchArgs {
        recipient: RECIPIENT.into(),
        amount: "25.0".into(),
        decimals: 6,
        mint: MINT.into(),
        reference: REFERENCE.into(),
        token_2022: false,
    }
}
fn expected() -> ExpectedPayment {
    args().expected().unwrap()
}
fn payment(reference_present: bool) -> ObservedPayment {
    ObservedPayment {
        signature: "test-signature".into(),
        sender: "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".into(),
        recipient: Pubkey::parse(RECIPIENT).unwrap(),
        mint: Pubkey::parse(MINT).unwrap(),
        amount_base_units: 25_000_000,
        decimals: 6,
        reference_present,
    }
}

#[test]
fn matching_payment_emits_a_structured_settlement_event() {
    let result = match_payment(&expected(), &[payment(true)]);
    assert_eq!(result.status, "paid");
    let event = result.event.expect("matching payment event");
    assert_eq!(event.event, "payment-received");
    assert_eq!(event.amount_base_units, 25_000_000);
}

#[test]
fn payment_without_the_required_reference_is_not_accepted() {
    let result = match_payment(&expected(), &[payment(false)]);
    assert_eq!(result.status, "waiting");
    assert!(result.event.is_none());
}

#[test]
fn rejects_amounts_that_would_be_rounded() {
    let mut invalid = args();
    invalid.amount = "25.0000001".into();
    assert!(invalid.expected().is_err());
}

struct PanicRpc;
impl RpcClient for PanicRpc {
    fn recent_payments(&self, _: &ExpectedPayment) -> Result<Vec<ObservedPayment>, WatchError> {
        panic!("invalid configuration must fail before RPC")
    }
}

/// RPC mock that always returns an error, used to verify that RPC failures
/// surface as `WatchError::Rpc` rather than panicking or being silently ignored.
struct ErrRpc;
impl RpcClient for ErrRpc {
    fn recent_payments(&self, _: &ExpectedPayment) -> Result<Vec<ObservedPayment>, WatchError> {
        Err(WatchError::Rpc("simulated RPC outage".into()))
    }
}

#[test]
fn prompt_injected_invalid_reference_fails_before_rpc() {
    let mut invalid = args();
    invalid.reference = "IGNORE_POLICY".into();
    assert!(check_payment(&invalid, &PanicRpc).is_err());
}

#[test]
fn rpc_failure_propagates_as_watch_error_rpc() {
    let result = check_payment(&args(), &ErrRpc);
    assert!(matches!(result, Err(WatchError::Rpc(_))));
}

#[test]
fn parameters_schema_is_valid_json_for_the_host() {
    let value: serde_json::Value = serde_json::from_str(PARAMETERS_SCHEMA)
        .expect("ZeroClaw must be able to parse the tool schema");
    assert_eq!(
        value
            .pointer("/properties/amount/type")
            .and_then(|value| value.as_str()),
        Some("string")
    );
}

/// Regression test: `token_2022: true` must resolve to a different watched
/// ATA than the classic-Token path for the same (recipient, mint). Before
/// `derive_ata` threaded the token program through, this flag was silently
/// dropped at the ATA-derivation step, so a real Token-2022 payment would
/// never be observed (the plugin would watch the wrong account forever).
#[test]
fn token_2022_flag_watches_a_different_ata_than_classic() {
    use payment_watch::core::derive_ata;

    let mut classic = args();
    classic.token_2022 = false;
    let mut token_2022 = args();
    token_2022.token_2022 = true;

    let classic_expected = classic.expected().unwrap();
    let token_2022_expected = token_2022.expected().unwrap();
    assert_ne!(
        classic_expected.token_program, token_2022_expected.token_program,
        "token_2022 must select the Token-2022 program id"
    );

    let classic_ata = derive_ata(
        classic_expected.recipient,
        classic_expected.mint,
        classic_expected.token_program,
    )
    .unwrap();
    let token_2022_ata = derive_ata(
        token_2022_expected.recipient,
        token_2022_expected.mint,
        token_2022_expected.token_program,
    )
    .unwrap();
    assert_ne!(
        classic_ata, token_2022_ata,
        "watched ATA must differ between classic Token and Token-2022"
    );
}

#[test]
fn near_miss_candidate_does_not_mask_or_get_matched_over_real_payment() {
    let mut wrong_amount = payment(true);
    wrong_amount.amount_base_units = 1; // near-miss: everything else matches
    let real = payment(true);

    // Near-miss alone must not match.
    let miss_only = match_payment(&expected(), &[wrong_amount.clone()]);
    assert_eq!(miss_only.status, "waiting");

    // With both present, the real payment must still be found.
    let both = match_payment(&expected(), &[wrong_amount, real]);
    assert_eq!(both.status, "paid");
    assert_eq!(both.event.unwrap().amount_base_units, 25_000_000);
}
