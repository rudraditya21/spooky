use super::*;

pub(super) fn resolve_primary_from_radix_prefix<T>(
    dcid: &[u8],
    connections: &HashMap<Arc<[u8]>, T>,
    cid_routes: &mut HashMap<Arc<[u8]>, Arc<[u8]>>,
    cid_radix: &mut CidRadix,
) -> Option<Arc<[u8]>> {
    let matched_cid = cid_radix.longest_prefix_match(dcid)?;

    if connections.contains_key(matched_cid.as_ref()) {
        return Some(matched_cid);
    }

    if let Some(primary) = cid_routes.get(matched_cid.as_ref()).cloned() {
        if connections.contains_key(primary.as_ref()) {
            return Some(primary);
        }
        cid_routes.remove(matched_cid.as_ref());
    }

    cid_radix.remove(matched_cid.as_ref());
    None
}

pub(crate) fn purge_connection_routes(
    cid_routes: &mut HashMap<Arc<[u8]>, Arc<[u8]>>,
    cid_radix: &mut CidRadix,
    peer_routes: &mut HashMap<std::net::SocketAddr, Arc<[u8]>>,
    primary_scid: &Arc<[u8]>,
    routing_scids: &std::collections::HashSet<Arc<[u8]>>,
    peer_address: &std::net::SocketAddr,
) {
    cid_radix.remove(primary_scid.as_ref());
    cid_routes.remove(primary_scid.as_ref());
    for cid in routing_scids {
        cid_radix.remove(cid.as_ref());
        cid_routes.remove(cid.as_ref());
    }
    peer_routes.remove(peer_address);
}

pub(crate) struct ConnectionRoutes {
    pub primary_scid: Arc<[u8]>,
    pub routing_scids: std::collections::HashSet<Arc<[u8]>>,
    pub peer_address: std::net::SocketAddr,
}

impl From<&crate::runtime::connection::quic::QuicConnection> for ConnectionRoutes {
    fn from(c: &crate::runtime::connection::quic::QuicConnection) -> Self {
        Self {
            primary_scid: Arc::clone(&c.primary_scid),
            routing_scids: c.routing_scids.clone(),
            peer_address: c.peer_address,
        }
    }
}

pub(crate) fn sweep_closed_connections<C, F>(
    connections: &mut HashMap<Arc<[u8]>, C>,
    cid_routes: &mut HashMap<Arc<[u8]>, Arc<[u8]>>,
    cid_radix: &mut CidRadix,
    peer_routes: &mut HashMap<std::net::SocketAddr, Arc<[u8]>>,
    to_remove: Vec<Arc<[u8]>>,
    routes_of: F,
) where
    F: Fn(&C) -> ConnectionRoutes,
{
    for scid in to_remove {
        if let Some(connection) = connections.remove(&scid) {
            let routes = routes_of(&connection);
            purge_connection_routes(
                cid_routes,
                cid_radix,
                peer_routes,
                &routes.primary_scid,
                &routes.routing_scids,
                &routes.peer_address,
            );
        }
    }
}
