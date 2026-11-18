//! Conversion from validated Hickory messages to core responses.

use hickory_proto::op::{Message, ResponseCode};
use nano_dns_core::error::Result as CoreResult;
use nano_dns_core::model::Response as CoreResponse;

use crate::error::ResolverError;

/// Convert a validated Hickory message into the core response representation.
pub(crate) fn into_core_response(message: Message) -> CoreResult<CoreResponse> {
    let ttl_secs = message
        .answers
        .iter()
        .map(|record| record.ttl)
        .min()
        .unwrap_or_else(|| {
            message
                .authorities
                .iter()
                .filter(|record| record.record_type() == hickory_proto::rr::RecordType::SOA)
                .map(|record| record.ttl)
                .min()
                .unwrap_or_default()
        });
    let negative = message.metadata.response_code == ResponseCode::NXDomain
        || (message.metadata.response_code == ResponseCode::NoError && message.answers.is_empty());
    let bytes = message
        .to_vec()
        .map_err(|error| ResolverError::Encode(error.to_string()))?;

    Ok(CoreResponse {
        bytes,
        ttl_secs,
        negative,
        cache_hit: false,
    })
}
