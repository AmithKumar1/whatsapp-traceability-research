from opentrace.protocols.traceback2019_tree import demo_tree, TraceTree


def test_tree_trace_recovers_branching_structure():
    _, _, tree = demo_tree()
    assert tree == TraceTree(0, (TraceTree(1, (TraceTree(2), TraceTree(3))),))
