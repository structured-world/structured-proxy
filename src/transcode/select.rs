//! Which annotated RPCs become REST routes.

use std::sync::Arc;

use prost_reflect::{DescriptorPool, MethodDescriptor};

/// The RPCs transcoded to REST: every one with a `google.api.http` rule, or
/// only the services and methods named.
///
/// # Examples
///
/// ```
/// use structured_proxy::transcode::RpcSelection;
///
/// let pool = prost_reflect::DescriptorPool::new();
/// // An empty list selects every annotated RPC.
/// let all = RpcSelection::new(&pool, Vec::<String>::new()).unwrap();
/// # let _ = all;
/// // A name the descriptors do not hold is an error.
/// assert!(RpcSelection::new(&pool, ["acme.v1.Orders"]).is_err());
/// ```
#[derive(Clone, Debug, Default)]
pub struct RpcSelection {
    names: Arc<[Name]>,
}

/// A selected service, or one method of it.
#[derive(Debug)]
struct Name {
    service: String,
    method: Option<String>,
}

impl RpcSelection {
    /// `names` out of `pool`: `package.Service` for every RPC of a service,
    /// `package.Service/Method` for one; none selects every annotated RPC.
    ///
    /// # Errors
    ///
    /// A name that is not a service, or a method of a service, of `pool`: a
    /// typo would otherwise leave its routes silently unmounted.
    pub fn new(
        pool: &DescriptorPool,
        names: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<Self, String> {
        let names = names
            .into_iter()
            .map(|name| {
                let name = name.as_ref();
                let (service, method) = match name.split_once('/') {
                    Some((service, method)) => (service, Some(method)),
                    None => (name, None),
                };
                let known = pool.get_service_by_name(service).is_some_and(|found| {
                    method.is_none_or(|method| found.methods().any(|m| m.name() == method))
                });
                if !known {
                    return Err(format!(
                        "{name:?} is not a service or method of the proto descriptors"
                    ));
                }
                Ok(Name {
                    service: service.to_owned(),
                    method: method.map(str::to_owned),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            names: names.into(),
        })
    }

    /// Whether every annotated RPC is transcoded.
    pub(crate) fn is_all(&self) -> bool {
        self.names.is_empty()
    }

    /// Whether `method` is transcoded.
    pub(crate) fn selects(&self, method: &MethodDescriptor) -> bool {
        self.is_all() || {
            let service = method.parent_service();
            self.names.iter().any(|name| {
                name.service == service.full_name()
                    && name.method.as_deref().is_none_or(|m| m == method.name())
            })
        }
    }
}
