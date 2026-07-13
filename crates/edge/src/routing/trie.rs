use crate::routing::{
    decision::RouteDecisionReason, matcher::best_matching_route_with_reason, route::IndexedRoute,
};

#[derive(Default)]
pub struct TrieNode {
    pub routes: Vec<IndexedRoute>,
    children: Vec<TrieEdge>,
}

#[derive(Default)]
struct TrieEdge {
    byte: u8,
    node: Box<TrieNode>,
}

#[derive(Default)]
pub struct RouteTrie {
    root: TrieNode,
}

impl TrieNode {
    fn update_route(&mut self, candidate: IndexedRoute) {
        if let Some(existing) = self
            .routes
            .iter_mut()
            .find(|route| route.upstream_idx == candidate.upstream_idx)
        {
            *existing = candidate;
            return;
        }
        self.routes.push(candidate);
    }

    #[inline(always)]
    fn child(&self, byte: u8) -> Option<&TrieNode> {
        match self.children.binary_search_by_key(&byte, |edge| edge.byte) {
            Ok(idx) => Some(self.children[idx].node.as_ref()),
            Err(_) => None,
        }
    }

    #[inline(always)]
    fn child_or_insert(&mut self, byte: u8) -> &mut TrieNode {
        match self.children.binary_search_by_key(&byte, |edge| edge.byte) {
            Ok(idx) => self.children[idx].node.as_mut(),
            Err(idx) => {
                self.children.insert(
                    idx,
                    TrieEdge {
                        byte,
                        node: Box::<TrieNode>::default(),
                    },
                );
                self.children[idx].node.as_mut()
            }
        }
    }
}

impl RouteTrie {
    pub fn insert(&mut self, prefix: Option<&str>, route: IndexedRoute) {
        let prefix = prefix.unwrap_or("");
        let mut node = &mut self.root;

        if prefix.is_empty() {
            node.update_route(route);
            return;
        }

        for byte in prefix.as_bytes() {
            node = node.child_or_insert(*byte);
        }

        node.update_route(route);
    }

    pub fn longest_prefix(
        &self,
        path: &str,
        method: Option<&str>,
        upstream_methods: &[Option<String>],
    ) -> Option<IndexedRoute> {
        self.longest_prefix_with_reason(path, method, upstream_methods)
            .map(|(route, _)| route)
    }

    pub fn longest_prefix_with_reason(
        &self,
        path: &str,
        method: Option<&str>,
        upstream_methods: &[Option<String>],
    ) -> Option<(IndexedRoute, Option<RouteDecisionReason>)> {
        let mut node = &self.root;
        let mut best =
            best_matching_route_with_reason(&node.routes, path, method, upstream_methods, None);

        for byte in path.as_bytes() {
            let Some(next) = node.child(*byte) else {
                break;
            };
            node = next;
            best =
                best_matching_route_with_reason(&node.routes, path, method, upstream_methods, best);
        }

        best
    }
}
