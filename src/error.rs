use ureq::Response;

/// A specialized `Result` type for operations in the TAXII client.
///
/// This type is used throughout the TAXII client library to return either successful results
/// or errors wrapped in a `Box<TaxiiError>`.
pub type Result<T> = std::result::Result<T, Box<TaxiiError>>;

/// Represents errors that can occur while interacting with a TAXII server.
///
/// This enum encapsulates various kinds of errors that can arise from TAXII client operations,
/// such as connection issues, authorization failures, and data parsing problems.
#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub enum TaxiiError {
    /// An error occurred while trying to connect to the TAXII server.
    /// Contains a message describing the error.
    TaxiiConnectionError(String),

    /// An authorization error occurred. This usually means that the credentials
    /// provided were incorrect or insufficient for the requested operation.
    /// Contains the server's response for further inspection.
    TaxiiAuthorizationError(Response),

    /// The requested resource was not found on the TAXII server.
    /// Contains the server's response for further inspection.
    TaxiiNotFound(Response),

    /// A generic error occurred. Used for various error conditions that do not
    /// fall under more specific categories.
    /// Contains the server's response for further inspection.
    TaxiiGenericError(Response),

    /// A error occured while trying to fetch collection IDs for a specified api root.
    TaxiiCollectionError(String),

    /// An error occurred while deserializing JSON data from the TAXII server.
    /// Contains a message describing the error.
    JsonDeserializationError(String),
}
