use super::{state::ControlApiState, *};

impl QUICListener {
    pub(super) fn handle_control_api_request(
        req: Request<Incoming>,
        state: &ControlApiState,
    ) -> Response<http_body_util::Full<bytes::Bytes>> {
        let route = match Self::gate_control_api_request(&req, state) {
            Ok(route) => route,
            Err(response) => return response,
        };
        match route {
            super::auth::ControlApiRoute::Health => Self::render_control_api_health(state),
            super::auth::ControlApiRoute::Ready => Self::render_control_api_ready(state),
            super::auth::ControlApiRoute::Runtime => Self::render_control_api_runtime_snapshot(state),
            super::auth::ControlApiRoute::ReloadCerts => Self::handle_control_api_reload_certs(state),
            super::auth::ControlApiRoute::ReloadRuntime => {
                Self::handle_control_api_runtime_reload(&req, state)
            }
            super::auth::ControlApiRoute::Restart => Self::handle_control_api_restart(state),
        }
    }
}
