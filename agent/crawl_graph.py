"""Directed crawl graph built from ZAP spider URLs.

Turns a flat URL list into a NetworkX DiGraph where edges represent
parent -> child path segments. An alert URL is reachable only if
nx.has_path() finds a valid route from root to the alert URL node.

No path = provably unreachable = instant false positive suppression
with no LLM call needed.
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

try:
    import networkx as nx
    NX_AVAILABLE = True
except ImportError:
    NX_AVAILABLE = False
    logger.warning("networkx not installed — graph reachability disabled")


def _url_to_node(url: str) -> str:
    """Normalise a URL to a consistent node key (scheme+host+path)."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/") or "/"


def build_crawl_graph(urls: list[str]) -> "nx.DiGraph | None":
    """
    Build a directed graph from a list of crawled URLs.

    Each URL becomes a node. Edges connect parent path segments to
    child path segments so reachability can be checked with has_path().

    Returns None if networkx is not available.
    """
    if not NX_AVAILABLE:
        return None

    graph = nx.DiGraph()

    for url in urls:
        node = _url_to_node(url)
        graph.add_node(node)

        # Add edge from parent path to this node
        parsed = urlparse(url)
        path_parts = parsed.path.rstrip("/").split("/")

        # Build parent path node
        if len(path_parts) > 1:
            parent_path = "/".join(path_parts[:-1]) or "/"
            parent_node = f"{parsed.scheme}://{parsed.netloc}{parent_path}"
            parent_node = parent_node.rstrip("/") or "/"
            if parent_node != node:
                graph.add_node(parent_node)
                graph.add_edge(parent_node, node)

        # Always connect root to first-level paths
        root = f"{parsed.scheme}://{parsed.netloc}"
        if root not in graph:
            graph.add_node(root)
        if root != node:
            graph.add_edge(root, node)

    logger.info("Crawl graph: %d nodes, %d edges", graph.number_of_nodes(), graph.number_of_edges())
    return graph


def is_reachable(graph: "nx.DiGraph", target_url: str) -> bool:
    """
    Return True if target_url is reachable from any root node in the graph.

    A URL is reachable if:
    1. It appears directly as a node in the graph, OR
    2. nx.has_path() finds a route from any root node to the target node
    """
    if graph is None:
        # If graph unavailable, assume reachable (conservative)
        return True

    target_node = _url_to_node(target_url)

    # Direct node membership check (fastest path)
    if target_node in graph:
        return True

    # Check partial match — URL might have query params stripped
    for node in graph.nodes:
        parsed_node = urlparse(node)
        if node == target_node:
            return True
        if parsed_node.path not in ("", "/") and target_node.startswith(f"{node}/"):
            return True

    # Graph path check from all root nodes (nodes with no incoming edges)
    roots = [n for n, d in graph.in_degree() if d == 0]
    for root in roots:
        try:
            if nx.has_path(graph, root, target_node):
                return True
        except nx.NodeNotFound:
            continue

    return False


def get_reachability_report(
    graph: "nx.DiGraph",
    alerts: list[dict],
) -> dict[str, bool]:
    """
    Return a dict mapping alert URL -> reachable bool for all alerts.
    """
    return {
        alert.get("url", ""): is_reachable(graph, alert.get("url", ""))
        for alert in alerts
    }


if __name__ == "__main__":
    sample_urls = [
        "http://juice-shop:3000/",
        "http://juice-shop:3000/login",
        "http://juice-shop:3000/register",
        "http://juice-shop:3000/rest/user/login",
        "http://juice-shop:3000/api/Products",
        "http://juice-shop:3000/rest/products/search",
    ]
    g = build_crawl_graph(sample_urls)
    print(f"Graph nodes: {g.number_of_nodes()}")
    print(f"Graph edges: {g.number_of_edges()}")

    test_urls = [
        "http://juice-shop:3000/login",           # in crawl
        "http://juice-shop:3000/administration",   # NOT in crawl
        "http://juice-shop:3000/rest/user/login",  # in crawl
    ]
    for url in test_urls:
        print(f"  {url}: reachable={is_reachable(g, url)}")
