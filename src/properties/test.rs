use super::*;

fn round_trip(properties: &Properties) -> Properties {
    let mut encoded = Vec::new();
    properties.encode(&mut encoded).unwrap();
    let mut cursor = 0;
    let decoded = Properties::parse(&encoded, &mut cursor).unwrap();
    assert_eq!(cursor, encoded.len());
    decoded
}

#[test]
fn empty_block_is_one_zero_byte() {
    let mut encoded = Vec::new();
    Properties::default().encode(&mut encoded).unwrap();
    assert_eq!(encoded, [0]);
    assert!(round_trip(&Properties::default()).is_empty());
}

#[test]
fn every_property_round_trips() {
    let properties = Properties {
        payload_format_indicator: Some(1),
        message_expiry_interval: Some(300),
        content_type: Some(Arc::from("application/json")),
        response_topic: Some(Arc::from("reply/here")),
        correlation_data: Some(Bytes::from_static(b"correlation")),
        subscription_identifiers: vec![1, MAX_VARIABLE_BYTE_INTEGER as u32],
        session_expiry_interval: Some(u32::MAX),
        assigned_client_identifier: Some(Arc::from("assigned")),
        server_keep_alive: Some(45),
        authentication_method: Some(Arc::from("token")),
        authentication_data: Some(Bytes::from_static(b"secret")),
        request_problem_information: Some(0),
        will_delay_interval: Some(12),
        request_response_information: Some(1),
        response_information: Some(Arc::from("response")),
        server_reference: Some(Arc::from("server")),
        reason_string: Some(Arc::from("reason")),
        receive_maximum: Some(10),
        topic_alias_maximum: Some(0),
        topic_alias: Some(1),
        maximum_qos: Some(1),
        retain_available: Some(0),
        user_properties: vec![
            (Arc::from("key"), Arc::from("first")),
            (Arc::from("key"), Arc::from("second")),
        ],
        maximum_packet_size: Some(1024),
        wildcard_subscription_available: Some(1),
        subscription_identifier_available: Some(0),
        shared_subscription_available: Some(1),
    };
    assert_eq!(round_trip(&properties), properties);
}

#[test]
fn duplicate_scalar_property_is_rejected() {
    let encoded = [
        10,
        id::SESSION_EXPIRY_INTERVAL,
        0,
        0,
        0,
        1,
        id::SESSION_EXPIRY_INTERVAL,
        0,
        0,
        0,
        2,
    ];
    let error = Properties::parse(&encoded, &mut 0).unwrap_err();
    assert!(matches!(
        error,
        MqttError::Protocol(Violation::DuplicateProperty(id::SESSION_EXPIRY_INTERVAL))
    ));
}

#[test]
fn unknown_property_is_rejected() {
    let error = Properties::parse(&[1, 0x7F], &mut 0).unwrap_err();
    assert!(matches!(
        error,
        MqttError::Protocol(Violation::UnknownProperty(0x7F))
    ));
}

#[test]
fn declared_block_boundary_is_enforced() {
    // The four-byte value exists in the outer packet, but only two of those
    // bytes were declared to belong to the property block.
    let encoded = [2, id::MESSAGE_EXPIRY_INTERVAL, 0, 0, 0, 1];
    let error = Properties::parse(&encoded, &mut 0).unwrap_err();
    assert!(matches!(error, MqttError::Codec(CodecError::UnexpectedEof)));
}

#[test]
fn boolean_like_values_are_validated_on_decode_and_encode() {
    let encoded = [2, id::PAYLOAD_FORMAT_INDICATOR, 2];
    let error = Properties::parse(&encoded, &mut 0).unwrap_err();
    assert!(matches!(
        error,
        MqttError::Protocol(Violation::MalformedProperty(id::PAYLOAD_FORMAT_INDICATOR))
    ));

    let properties = Properties {
        shared_subscription_available: Some(2),
        ..Properties::default()
    };
    let error = properties.encode(&mut Vec::new()).unwrap_err();
    assert!(matches!(
        error,
        MqttError::Protocol(Violation::MalformedProperty(
            id::SHARED_SUBSCRIPTION_AVAILABLE
        ))
    ));
}

#[test]
fn non_zero_values_are_validated_on_decode_and_encode() {
    for (property_id, encoded) in [
        (id::RECEIVE_MAXIMUM, vec![3, id::RECEIVE_MAXIMUM, 0, 0]),
        (id::TOPIC_ALIAS, vec![3, id::TOPIC_ALIAS, 0, 0]),
        (
            id::MAXIMUM_PACKET_SIZE,
            vec![5, id::MAXIMUM_PACKET_SIZE, 0, 0, 0, 0],
        ),
        (
            id::SUBSCRIPTION_IDENTIFIER,
            vec![2, id::SUBSCRIPTION_IDENTIFIER, 0],
        ),
    ] {
        let error = Properties::parse(&encoded, &mut 0).unwrap_err();
        assert!(matches!(
            error,
            MqttError::Protocol(Violation::MalformedProperty(id)) if id == property_id
        ));
    }

    for properties in [
        Properties {
            receive_maximum: Some(0),
            ..Properties::default()
        },
        Properties {
            topic_alias: Some(0),
            ..Properties::default()
        },
        Properties {
            maximum_packet_size: Some(0),
            ..Properties::default()
        },
        Properties {
            subscription_identifiers: vec![0],
            ..Properties::default()
        },
    ] {
        assert!(properties.encode(&mut Vec::new()).is_err());
    }
}

#[test]
fn variable_byte_integer_boundaries_are_canonical() {
    for value in [
        0,
        127,
        128,
        16_383,
        16_384,
        2_097_151,
        2_097_152,
        MAX_VARIABLE_BYTE_INTEGER,
    ] {
        let mut encoded = Vec::new();
        write_vbi(&mut encoded, value).unwrap();
        let mut cursor = 0;
        assert_eq!(read_vbi(&encoded, &mut cursor).unwrap(), value);
        assert_eq!(cursor, encoded.len());
        assert!(encoded.len() <= 4);
    }
}

#[test]
fn non_minimal_and_five_byte_variable_integers_are_rejected() {
    for encoded in [
        &[0x80, 0x00][..],
        &[0x81, 0x00][..],
        &[0x80, 0x80, 0x00][..],
        &[0x80, 0x80, 0x80, 0x80, 0x00][..],
    ] {
        assert!(read_vbi(encoded, &mut 0).is_err(), "{encoded:02x?}");
    }
    let error = write_vbi(&mut Vec::new(), MAX_VARIABLE_BYTE_INTEGER + 1).unwrap_err();
    assert!(matches!(
        error,
        MqttError::Codec(CodecError::VariableByteIntegerOutOfRange { .. })
    ));
}

#[test]
fn mqtt_strings_reject_null_on_decode_and_encode() {
    let encoded = [4, id::CONTENT_TYPE, 0, 1, 0];
    let error = Properties::parse(&encoded, &mut 0).unwrap_err();
    assert!(matches!(
        error,
        MqttError::Protocol(Violation::Utf8NullCharacter)
    ));

    let properties = Properties {
        content_type: Some(Arc::from("a\0b")),
        ..Properties::default()
    };
    assert!(matches!(
        properties.encode(&mut Vec::new()).unwrap_err(),
        MqttError::Protocol(Violation::Utf8NullCharacter)
    ));
}

#[test]
fn length_prefixed_values_reject_more_than_u16_bytes() {
    let properties = Properties {
        content_type: Some(Arc::from("x".repeat(u16::MAX as usize + 1))),
        ..Properties::default()
    };
    assert!(matches!(
        properties.encode(&mut Vec::new()).unwrap_err(),
        MqttError::Codec(CodecError::FieldTooLong { .. })
    ));
}

#[test]
fn authentication_data_requires_a_method() {
    let properties = Properties {
        authentication_data: Some(Bytes::from_static(b"secret")),
        ..Properties::default()
    };
    assert!(matches!(
        properties.encode(&mut Vec::new()).unwrap_err(),
        MqttError::Protocol(Violation::MalformedProperty(id::AUTHENTICATION_DATA))
    ));
}

#[test]
fn response_topic_must_be_a_topic_name() {
    for response_topic in ["", "reply/+", "reply/#"] {
        let properties = Properties {
            response_topic: Some(Arc::from(response_topic)),
            ..Properties::default()
        };
        assert!(properties.encode(&mut Vec::new()).is_err());
    }
}
