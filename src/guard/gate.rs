//! The guards decided as the request arrives, in pipeline order: a required
//! client address, maintenance mode, the concurrency limit and the rate limits
//! keyed before auth. One layer runs them all, with no boxed future and no
//! clone of the service behind it.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::extract::Request;
use axum::response::Response;
use http::header::RETRY_AFTER;
use http::HeaderValue;
use pin_project_lite::pin_project;
use tokio::sync::OwnedSemaphorePermit;
use tower::{Layer, Service};

use super::{reject, Class, Concurrency, Guards, Maintenance, Scope};
use crate::client_address::{ClientAddress, Resolution};
use crate::shield::matcher::Phase;
use crate::shield::{Decision, Report, Shield};

/// The guards of one class of traffic decided as the request arrives, each
/// with its scope.
pub(crate) struct Gate {
    require_client: Option<Arc<Scope>>,
    maintenance: Option<(Arc<Maintenance>, Arc<Scope>)>,
    concurrency: Option<(Arc<Concurrency>, Arc<Scope>)>,
    shield: Option<(Arc<Shield>, Arc<Scope>)>,
}

impl Gate {
    /// The layer of the guards of `guards` that cover `class`, or `None`
    /// when none does.
    pub(super) fn layer(guards: &Guards, class: Class) -> Option<GateLayer> {
        let covered = |scope: &Arc<Scope>| scope.covers(class);
        let gate = Self {
            require_client: guards.require_client.clone().filter(covered),
            maintenance: guards
                .maintenance
                .clone()
                .filter(|(_, scope)| covered(scope)),
            concurrency: guards
                .concurrency
                .clone()
                .filter(|(_, scope)| covered(scope)),
            shield: guards
                .shield
                .clone()
                .filter(|(shield, scope)| covered(scope) && shield.enforces(Phase::PreAuth)),
        };
        let empty = gate.require_client.is_none()
            && gate.maintenance.is_none()
            && gate.concurrency.is_none()
            && gate.shield.is_none();
        (!empty).then(|| GateLayer(Arc::new(gate)))
    }

    /// Run the guards on `request`: the answer of the first that turns it
    /// away, or what the response owes the ones that let it through.
    fn admit(&self, request: &Request) -> Admission {
        if let Some(scope) = &self.require_client {
            if applies(scope, request) {
                if let Some(refusal) = unresolved_client(request) {
                    return Admission::Refused(refusal);
                }
            }
        }
        if let Some((maintenance, scope)) = &self.maintenance {
            if applies(scope, request) && !maintenance.exempts(request.uri().path()) {
                let mut response = reject(tonic::Code::Unavailable, maintenance.message.clone());
                response
                    .headers_mut()
                    .insert(RETRY_AFTER, HeaderValue::from_static("300"));
                return Admission::Refused(response);
            }
        }
        let mut admitted = Admitted::default();
        if let Some((concurrency, scope)) = &self.concurrency {
            if applies(scope, request) {
                match concurrency.take() {
                    Some(slot) => admitted.slot = Some(slot),
                    None => return Admission::Refused(Concurrency::full()),
                }
            }
        }
        if let Some((shield, scope)) = &self.shield {
            if applies(scope, request) {
                match shield.decide(Phase::PreAuth, request) {
                    Decision::Pass => {}
                    // Turned away here, the request is not in flight: its
                    // slot is free again.
                    Decision::Reject(response) => return Admission::Refused(response),
                    Decision::Report(report) => admitted.report = Some(report),
                }
            }
        }
        Admission::Admitted(admitted)
    }
}

/// What the guards make of a request.
enum Admission {
    Admitted(Admitted),
    Refused(Response),
}

/// Whether a guard with `scope`, which covers the request's class, applies
/// to it.
fn applies(scope: &Scope, request: &Request) -> bool {
    !scope.narrows() || scope.matches(request)
}

/// `client_address.required`: a request whose address did not resolve is
/// refused, `INVALID_ARGUMENT` when a trusted proxy forwarded something
/// unreadable, `INTERNAL` when the server recorded no connection.
fn unresolved_client(request: &Request) -> Option<Response> {
    let resolution = request
        .extensions()
        .get::<ClientAddress>()
        .map_or(Resolution::Unavailable, ClientAddress::resolution);
    match resolution {
        Resolution::Peer(_) | Resolution::Forwarded(_) => None,
        Resolution::Invalid(invalid) => Some(reject(
            tonic::Code::InvalidArgument,
            format!("the client address a trusted proxy forwarded is {invalid}"),
        )),
        Resolution::Unavailable => Some(reject(
            tonic::Code::Internal,
            "no connection information to resolve the client address from",
        )),
    }
}

/// What the response of an admitted request owes the guards: the in-flight
/// slot it holds until its body ends, the rate-limit budget it reports.
#[derive(Default)]
struct Admitted {
    slot: Option<OwnedSemaphorePermit>,
    report: Option<Report>,
}

impl Admitted {
    fn settle(self, mut response: Response) -> Response {
        if let Some(report) = &self.report {
            report.apply(&mut response);
        }
        match self.slot {
            Some(slot) => response.map(|body| crate::held::until_end(body, slot)),
            None => response,
        }
    }
}

/// The layer of a [`Gate`].
#[derive(Clone)]
pub(crate) struct GateLayer(Arc<Gate>);

impl<S> Layer<S> for GateLayer {
    type Service = GateService<S>;

    fn layer(&self, inner: S) -> GateService<S> {
        GateService {
            gate: self.0.clone(),
            inner,
        }
    }
}

/// The service of a [`GateLayer`].
#[derive(Clone)]
pub(crate) struct GateService<S> {
    gate: Arc<Gate>,
    inner: S,
}

impl<S> Service<Request> for GateService<S>
where
    S: Service<Request, Response = Response, Error = Infallible>,
{
    type Response = Response;
    type Error = Infallible;
    type Future = GateFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        match self.gate.admit(&request) {
            Admission::Admitted(admitted) => GateFuture::Admitted {
                future: self.inner.call(request),
                admitted: Some(admitted),
            },
            Admission::Refused(response) => GateFuture::Refused {
                response: Some(response),
            },
        }
    }
}

pin_project! {
    /// The response future of a [`GateService`].
    #[project = GateProjection]
    pub(crate) enum GateFuture<F> {
        Admitted { #[pin] future: F, admitted: Option<Admitted> },
        Refused { response: Option<Response> },
    }
}

impl<F> Future for GateFuture<F>
where
    F: Future<Output = Result<Response, Infallible>>,
{
    type Output = Result<Response, Infallible>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            GateProjection::Admitted { future, admitted } => {
                let Ok(response) = std::task::ready!(future.poll(cx));
                let admitted = admitted.take().expect("polled after completion");
                Poll::Ready(Ok(admitted.settle(response)))
            }
            GateProjection::Refused { response } => {
                Poll::Ready(Ok(response.take().expect("polled after completion")))
            }
        }
    }
}
