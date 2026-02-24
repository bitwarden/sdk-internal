use ciborium::Value;

use crate::cose::{
    ContentNamespace, SAFE_CONTENT_NAMESPACE, SAFE_OBJECT_NAMESPACE, SafeObjectNamespace,
    extract_integer,
};

pub(super) enum ExtractionError {
    MissingNamespace,
    InvalidNamespace,
}

fn extract_safe_object_namespace(
    header: &coset::Header,
) -> Result<SafeObjectNamespace, ExtractionError> {
    match extract_integer(header, SAFE_OBJECT_NAMESPACE, "safe object namespace") {
        Ok(value) => value
            .try_into()
            .map_err(|_| ExtractionError::InvalidNamespace),
        Err(_) => Err(ExtractionError::MissingNamespace),
    }
}

fn extract_safe_content_namespace<T: ContentNamespace>(
    header: &coset::Header,
) -> Result<T, ExtractionError> {
    match extract_integer(header, SAFE_CONTENT_NAMESPACE, "safe content namespace") {
        Ok(value) => value
            .try_into()
            .map_err(|_| ExtractionError::InvalidNamespace),
        Err(_) => Err(ExtractionError::MissingNamespace),
    }
}

fn set_header_value(header: &mut coset::Header, label: i64, value: Value) {
    if let Some((_, existing_value)) =
        header
            .rest
            .iter_mut()
            .find(|(existing_label, _)| matches!(existing_label, coset::Label::Int(existing) if *existing == label))
    {
        *existing_value = value;
    } else {
        header.rest.push((coset::Label::Int(label), value));
    }
}

pub(super) fn set_safe_namespaces<T: ContentNamespace>(
    header: &mut coset::Header,
    object_namespace: SafeObjectNamespace,
    content_namespace: T,
) {
    set_header_value(
        header,
        SAFE_OBJECT_NAMESPACE,
        Value::from(object_namespace as i64),
    );
    set_header_value(
        header,
        SAFE_CONTENT_NAMESPACE,
        Value::from(Into::<i128>::into(content_namespace) as i64),
    );
}

/// Validates the provided header contains the expected object and content namespace.
/// For backward compatibility, missing values are OK, but incorrect values are not.
/// The validation happens individually for both namespace layers, and either one
/// missing with the other being present is OK.
pub(super) fn validate_safe_namespaces<T: ContentNamespace>(
    header: &coset::Header,
    expected_object_namespace: SafeObjectNamespace,
    expected_content_namespace: T,
) -> Result<(), ExtractionError> {
    match extract_safe_object_namespace(header) {
        Ok(ns) if ns == expected_object_namespace => (),
        // If the namespace is present but doesn't match, return an error immediately.
        Ok(_) => return Err(ExtractionError::InvalidNamespace),
        // If the namespace is missing, do not validate for backward compatibility
        Err(ExtractionError::MissingNamespace) => (),
        // If the namespace is present but invalid (e.g., not an integer or out of range), return an
        // error.
        Err(ExtractionError::InvalidNamespace) => return Err(ExtractionError::InvalidNamespace),
    }

    match extract_safe_content_namespace::<T>(header) {
        Ok(ns) if ns == expected_content_namespace => Ok(()),
        // If the namespace is present but doesn't match, return an error immediately.
        Ok(_) => Err(ExtractionError::InvalidNamespace),
        // If the namespace is missing, do not validate for backward compatibility
        Err(ExtractionError::MissingNamespace) => Ok(()),
        // If the namespace is present but invalid (e.g., not an integer or out of range), return an
        // error.
        Err(ExtractionError::InvalidNamespace) => Err(ExtractionError::InvalidNamespace),
    }
}

#[cfg(test)]
mod tests {
    use ciborium::Value;

    use super::*;
    use crate::{cose::SAFE_OBJECT_NAMESPACE, safe::DataEnvelopeNamespace};

    fn count_label(header: &coset::Header, label: i64) -> usize {
        header
            .rest
            .iter()
            .filter(
                |(existing_label, _)| {
                    matches!(existing_label, coset::Label::Int(existing) if *existing == label)
                },
            )
            .count()
    }

    fn extract_safe_namespaces<T: ContentNamespace>(
        header: &coset::Header,
    ) -> Result<(SafeObjectNamespace, T), ExtractionError> {
        let object_namespace = extract_safe_object_namespace(header)?;
        let content_namespace = extract_safe_content_namespace(header)?;

        Ok((object_namespace, content_namespace))
    }

    #[test]
    fn set_safe_namespaces_sets_both_namespace_labels() {
        let mut header = coset::HeaderBuilder::new().build();

        set_safe_namespaces(
            &mut header,
            SafeObjectNamespace::DataEnvelope,
            DataEnvelopeNamespace::ExampleNamespace,
        );

        let extracted = extract_safe_namespaces::<DataEnvelopeNamespace>(&header);
        assert!(matches!(
            extracted,
            Ok((
                SafeObjectNamespace::DataEnvelope,
                DataEnvelopeNamespace::ExampleNamespace
            ))
        ));
    }

    #[test]
    fn set_safe_namespaces_overwrites_existing_namespace_values() {
        let mut header = coset::HeaderBuilder::new()
            .value(SAFE_OBJECT_NAMESPACE, Value::from(999_i64))
            .value(SAFE_CONTENT_NAMESPACE, Value::from(999_i64))
            .build();

        set_safe_namespaces(
            &mut header,
            SafeObjectNamespace::DataEnvelope,
            DataEnvelopeNamespace::ExampleNamespace,
        );

        assert_eq!(count_label(&header, SAFE_OBJECT_NAMESPACE), 1);
        assert_eq!(count_label(&header, SAFE_CONTENT_NAMESPACE), 1);
        assert!(matches!(
            extract_safe_namespaces::<DataEnvelopeNamespace>(&header),
            Ok((
                SafeObjectNamespace::DataEnvelope,
                DataEnvelopeNamespace::ExampleNamespace
            ))
        ));
    }

    #[test]
    fn extract_safe_namespaces_fails_when_namespace_missing() {
        let header = coset::HeaderBuilder::new().build();

        assert!(matches!(
            extract_safe_namespaces::<DataEnvelopeNamespace>(&header),
            Err(ExtractionError::MissingNamespace)
        ));
    }

    #[test]
    fn extract_safe_namespaces_fails_when_namespace_invalid() {
        let header = coset::HeaderBuilder::new()
            .value(
                SAFE_OBJECT_NAMESPACE,
                Value::from(SafeObjectNamespace::DataEnvelope as i64),
            )
            .value(SAFE_CONTENT_NAMESPACE, Value::from(999_i64))
            .build();

        assert!(matches!(
            extract_safe_namespaces::<DataEnvelopeNamespace>(&header),
            Err(ExtractionError::InvalidNamespace)
        ));
    }

    #[test]
    fn validate_safe_namespaces_allows_missing_labels_for_backwards_compat() {
        let header = coset::HeaderBuilder::new().build();

        let result = validate_safe_namespaces(
            &header,
            SafeObjectNamespace::DataEnvelope,
            DataEnvelopeNamespace::ExampleNamespace,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn validate_safe_namespaces_rejects_namespace_mismatch() {
        let mut header = coset::HeaderBuilder::new().build();
        set_safe_namespaces(
            &mut header,
            SafeObjectNamespace::DataEnvelope,
            DataEnvelopeNamespace::ExampleNamespace,
        );

        let result = validate_safe_namespaces(
            &header,
            SafeObjectNamespace::DataEnvelope,
            DataEnvelopeNamespace::ExampleNamespace2,
        );
        assert!(matches!(result, Err(ExtractionError::InvalidNamespace)));
    }
}
