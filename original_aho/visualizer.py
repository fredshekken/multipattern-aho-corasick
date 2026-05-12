"""
Aho-Corasick Trie Visualizer — Enhanced
========================================
Features:
  - Light / Dark mode toggle
  - Character-by-character text traversal (Prev / Next + arrow keys)
  - Show / Hide trie button
  - Collapsible legend [ - / + ]
  - Hover canvas: failure links fade
  - Leave canvas: failure links restore
  - Active state highlighted in green during traversal
"""

import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.lines as mlines
import matplotlib.widgets as mwidgets
import networkx as nx
from collections import defaultdict, deque


# ──────────────────────────────────────────────
#  THEMES
# ──────────────────────────────────────────────
THEMES = {
    "light": {
        "fig_bg":      "#FFFFFF",
        "ax_bg":       "#FFFFFF",
        "node_root":   "#FFFFFF",
        "node_output": "#F39C12",
        "node_normal": "#1A6B8A",
        "node_active": "#27AE60",
        "node_border": "#1A1A2E",
        "edge_trie":   "#1A1A2E",
        "edge_fail":   "#E74C3C",
        "edge_label":  "#E67E22",
        "text_root":   "#1A1A2E",
        "text_normal": "#FFFFFF",
        "text_output": "#1A1A2E",
        "text_active": "#FFFFFF",
        "legend_bg":   "#F5F5F5",
        "legend_edge": "#CCCCCC",
        "legend_text": "#1A1A2E",
        "btn_bg":      "#1A1A2E",
        "btn_fg":      "#FFFFFF",
        "btn_hover":   "#2E2E4E",
        "info_bg":     "#EEF2FF",
        "info_text":   "#1A1A2E",
        "match_bg":    "#D4EDDA",
        "match_text":  "#155724",
    },
    "dark": {
        "fig_bg":      "#1A1A2E",
        "ax_bg":       "#1A1A2E",
        "node_root":   "#2E2E4E",
        "node_output": "#E67E22",
        "node_normal": "#0D6EFD",
        "node_active": "#2ECC71",
        "node_border": "#AAAACC",
        "edge_trie":   "#AAAACC",
        "edge_fail":   "#FF6B6B",
        "edge_label":  "#FFC107",
        "text_root":   "#FFFFFF",
        "text_normal": "#FFFFFF",
        "text_output": "#FFFFFF",
        "text_active": "#FFFFFF",
        "legend_bg":   "#2E2E4E",
        "legend_edge": "#555577",
        "legend_text": "#FFFFFF",
        "btn_bg":      "#0D6EFD",
        "btn_fg":      "#FFFFFF",
        "btn_hover":   "#1A85FF",
        "info_bg":     "#2E2E4E",
        "info_text":   "#FFFFFF",
        "match_bg":    "#1E4D2B",
        "match_text":  "#A8E6B5",
    },
}


# ──────────────────────────────────────────────
#  LAYOUT HELPERS
# ──────────────────────────────────────────────
def _bfs_levels(trie_edge_pairs, root, all_nodes):
    children = defaultdict(list)
    for (u, v) in trie_edge_pairs:
        children[u].append(v)
    level = {root: 0}
    queue = deque([root])
    while queue:
        node = queue.popleft()
        for child in children[node]:
            if child not in level:
                level[child] = level[node] + 1
                queue.append(child)
    max_level = max(level.values()) if level else 0
    for n in all_nodes:
        if n not in level:
            level[n] = max_level + 1
    return level


def _compute_positions(trie_edge_pairs, root, all_nodes, x_gap=7.0, y_gap=3.8):
    level = _bfs_levels(trie_edge_pairs, root, all_nodes)

    children = defaultdict(list)
    for (u, v) in trie_edge_pairs:
        children[u].append(v)

    # DFS in-order traversal: each leaf gets a unique integer slot.
    # Internal nodes are centered over their children's slots.
    # This GUARANTEES no two trie nodes share an x position.
    leaf_counter = [0]
    node_x = {}

    def dfs_assign(node):
        kids = children[node]
        if not kids:
            node_x[node] = leaf_counter[0] * x_gap
            leaf_counter[0] += 1
            return
        for k in kids:
            dfs_assign(k)
        node_x[node] = (node_x[kids[0]] + node_x[kids[-1]]) / 2

    dfs_assign(root)

    # For any nodes not reachable via trie edges (DFA shortcut nodes),
    # assign them past the rightmost existing x with minimum spacing enforced
    # by a per-level sweep.
    by_level = defaultdict(list)
    for node in all_nodes:
        by_level[level[node]].append(node)

    for lv in sorted(by_level):
        row = sorted(by_level[lv], key=lambda n: node_x.get(n, float('inf')))
        last_x = None
        for n in row:
            if n not in node_x:
                node_x[n] = (last_x + x_gap) if last_x is not None else 0
            elif last_x is not None and node_x[n] - last_x < x_gap:
                node_x[n] = last_x + x_gap
            last_x = node_x[n]

    pos = {}
    for node in all_nodes:
        lv = level.get(node, 0)
        pos[node] = (node_x.get(node, 0), -lv * y_gap)
    return pos


# ──────────────────────────────────────────────
#  MAIN VISUALIZER
# ──────────────────────────────────────────────
def visualize_trie(ac, title="Aho-Corasick Trie", input_text=""):
    structure  = ac.get_trie_structure()
    nodes      = structure["nodes"]
    edges      = structure["edges"]
    fail_edges = structure["failure_edges"]

    all_node_ids = [n["id"] for n in nodes]
    node_info    = {n["id"]: n for n in nodes}

    trie_edge_pairs = []
    edge_char_map   = {}
    for e in edges:
        parent_label = node_info[e["from"]]["label"]
        child_label  = node_info[e["to"]]["label"]
        base = "" if parent_label == "ROOT" else parent_label
        if child_label == base + e["char"]:
            trie_edge_pairs.append((e["from"], e["to"]))
            edge_char_map[(e["from"], e["to"])] = e["char"]

    G = nx.DiGraph()
    G.add_nodes_from(all_node_ids)
    for (u, v) in trie_edge_pairs:
        G.add_edge(u, v)

    pos = _compute_positions(trie_edge_pairs, root=0, all_nodes=all_node_ids)

    x_vals = [p[0] for p in pos.values()]
    y_vals = [p[1] for p in pos.values()]
    fig_w  = max(24, (max(x_vals) - min(x_vals)) * 1.5 + 6)
    fig_h  = max(15, (max(y_vals) - min(y_vals)) * 1.3 + 7)

    fig, ax = plt.subplots(figsize=(fig_w, fig_h))
    plt.subplots_adjust(bottom=0.20)

    # ── Pre-compute traversal steps ──────────────────────────────
    # steps[i] = (char_index, state_after_reading, matched_patterns)
    # steps[0] = (-1, 0, [])  → initial, no char read yet
    steps = []
    if input_text:
        curr = 0
        steps.append((-1, 0, []))
        for i, ch in enumerate(input_text):
            curr = ac.goto[curr].get(ch, 0)
            matched = []
            if ac.out[curr] > 0:
                for j in range(len(ac.patterns)):
                    if ac.out[curr] & (1 << j):
                        matched.append(ac.patterns[j])
            steps.append((i, curr, matched))

    # ── Mutable state ─────────────────────────────────────────────
    st = {
        "theme":          "light",
        "trie_visible":   True,
        "legend_visible": True,
        "step":           0,
        "active_node":    0,
    }

    SHRINK = 50

    # ── Redraw ────────────────────────────────────────────────────
    def redraw():
        T = THEMES[st["theme"]]
        fig.patch.set_facecolor(T["fig_bg"])
        ax.set_facecolor(T["ax_bg"])
        ax.cla()
        ax.axis("off")

        # clear old info texts
        for txt in getattr(fig, "_info_texts", []):
            try:
                txt.remove()
            except Exception:
                pass
        fig._info_texts = []

        if not st["trie_visible"]:
            _draw_info_panel(T)
            fig.canvas.draw_idle()
            return

        active = st["active_node"]

        # failure links
        fail_arts = []
        for fe in fail_edges:
            u, v = fe["from"], fe["to"]
            if u == v or u not in pos or v not in pos:
                continue
            x1, y1 = pos[u]
            x2, y2 = pos[v]
            dx = x1 - x2
            rad = 0.3 + min(0.45, abs(dx) * 0.03)
            rad = rad if u % 2 == 0 else -rad
            ann = ax.annotate(
                "", xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(
                    arrowstyle="-|>",
                    color=T["edge_fail"],
                    lw=1.1,
                    linestyle="dashed",
                    connectionstyle=f"arc3,rad={rad}",
                    shrinkA=SHRINK,
                    shrinkB=SHRINK,
                ),
                zorder=2
            )
            fail_arts.append(ann)

        # trie edges
        nx.draw_networkx_edges(
            G, pos,
            edgelist=trie_edge_pairs,
            edge_color=T["edge_trie"],
            arrows=True,
            arrowsize=15,
            arrowstyle="-|>",
            width=1.8,
            connectionstyle="arc3,rad=0.05",
            min_source_margin=SHRINK,
            min_target_margin=SHRINK,
            ax=ax
        )
        nx.draw_networkx_edge_labels(
            G, pos,
            edge_labels=edge_char_map,
            font_size=10,
            font_color=T["edge_label"],
            font_weight="bold",
            bbox=dict(boxstyle="round,pad=0.18",
                      fc=T["fig_bg"], ec="none", alpha=0.92),
            ax=ax
        )

        # nodes
        node_colors = []
        for nid in all_node_ids:
            n = node_info[nid]
            if nid == active and steps:
                node_colors.append(T["node_active"])
            elif nid == 0:
                node_colors.append(T["node_root"])
            elif n["is_output"]:
                node_colors.append(T["node_output"])
            else:
                node_colors.append(T["node_normal"])

        nx.draw_networkx_nodes(
            G, pos,
            nodelist=all_node_ids,
            node_color=node_colors,
            node_size=2400,
            edgecolors=T["node_border"],
            linewidths=2.5,
            ax=ax
        )

        for nid in all_node_ids:
            x, y = pos[nid]
            n    = node_info[nid]
            lbl  = n["label"] if n["label"] != "ROOT" else "ROOT"
            if len(lbl) > 7:
                lbl = lbl[-6:]
            if nid == active and steps:
                txt_color = T["text_active"]
            elif nid == 0:
                txt_color = T["text_root"]
            elif n["is_output"]:
                txt_color = T["text_output"]
            else:
                txt_color = T["text_normal"]
            ax.text(x, y, f"{nid}\n{lbl}",
                    ha="center", va="center",
                    fontsize=9, fontweight="bold",
                    color=txt_color, zorder=6)

        # legend
        legend_items = [
            mpatches.Patch(facecolor=T["node_root"],   edgecolor=T["node_border"], linewidth=2, label="Root (State 0)"),
            mpatches.Patch(facecolor=T["node_output"], edgecolor=T["node_border"], linewidth=2, label="Output State (Match)"),
            mpatches.Patch(facecolor=T["node_normal"], edgecolor=T["node_border"], linewidth=2, label="Normal State"),
            mpatches.Patch(facecolor=T["node_active"], edgecolor=T["node_border"], linewidth=2, label="Active State"),
            mlines.Line2D([], [], color=T["edge_trie"], linewidth=2,
                          marker=">", markersize=8, label="Trie Transition"),
            mlines.Line2D([], [], color=T["edge_fail"], linewidth=2,
                          linestyle="dashed", marker=">", markersize=8, label="Failure Link"),
        ]
        legend = ax.legend(
            handles=legend_items,
            loc="lower left",
            facecolor=T["legend_bg"],
            edgecolor=T["legend_edge"],
            labelcolor=T["legend_text"],
            fontsize=10,
            framealpha=0.95,
            title=title,
            title_fontsize=11,
        )
        legend.set_visible(st["legend_visible"])
        if legend.get_visible():
            legend.get_title().set_fontweight("bold")
            legend.get_title().set_color(T["legend_text"])

        # hover: fade failure links
        def _set_fail_alpha(alpha):
            for ann in fail_arts:
                try:
                    ann.arrow_patch.set_alpha(alpha)
                except Exception:
                    try:
                        for child in ann.get_children():
                            child.set_alpha(alpha)
                    except Exception:
                        pass
            fig.canvas.draw_idle()

        def on_enter(event):
            if event.inaxes == ax:
                _set_fail_alpha(0.08)

        def on_leave(event):
            _set_fail_alpha(1.0)

        for cid in getattr(fig, "_hover_cids", []):
            try:
                fig.canvas.mpl_disconnect(cid)
            except Exception:
                pass
        cid1 = fig.canvas.mpl_connect("axes_enter_event", on_enter)
        cid2 = fig.canvas.mpl_connect("axes_leave_event", on_leave)
        fig._hover_cids = [cid1, cid2]

        _draw_info_panel(T)
        fig.canvas.draw_idle()

    def _draw_info_panel(T):
        if not steps:
            return
        step_idx = st["step"]
        char_idx, curr_state, matched = steps[step_idx]

        if char_idx == -1:
            input_display = input_text
            step_label    = "Initial state — no character read yet"
        else:
            ch = input_text[char_idx]
            before = input_text[:char_idx]
            after  = input_text[char_idx + 1:]
            input_display = f"{before}[{ch}]{after}"
            step_label = (f"Step {step_idx}/{len(steps)-1}  |  "
                          f"Reading: '{ch}'  |  → State {curr_state}")
            if matched:
                step_label += f"  |  ✓ Match: {matched}"

        t1 = fig.text(0.5, 0.13,
                      f"Input:  {input_display}",
                      ha="center", va="center", fontsize=11,
                      color=T["info_text"],
                      bbox=dict(boxstyle="round,pad=0.4",
                                fc=T["info_bg"], ec=T["legend_edge"], alpha=0.9))
        t2 = fig.text(0.5, 0.08,
                      step_label,
                      ha="center", va="center", fontsize=11,
                      color=T["match_text"] if matched else T["info_text"],
                      fontweight="bold" if matched else "normal",
                      bbox=dict(boxstyle="round,pad=0.4",
                                fc=T["match_bg"] if matched else T["info_bg"],
                                ec=T["legend_edge"], alpha=0.9))
        fig._info_texts = [t1, t2]

    # ── Buttons ───────────────────────────────────────────────────
    # Row: [◀ Prev]  [Next ▶]   [Hide/Show Trie]  [Dark/Light Mode]  [− / + Legend]

    def _make_btn(spec, label):
        T = THEMES[st["theme"]]
        bax = fig.add_axes(spec)
        btn = mwidgets.Button(bax, label,
                               color=T["btn_bg"], hovercolor=T["btn_hover"])
        btn.label.set_color(T["btn_fg"])
        btn.label.set_fontsize(9)
        btn.label.set_fontweight("bold")
        return btn

    btn_prev   = _make_btn([0.06, 0.03, 0.09, 0.04], "◀  Prev")
    btn_next   = _make_btn([0.16, 0.03, 0.09, 0.04], "Next  ▶")
    btn_trie   = _make_btn([0.32, 0.03, 0.14, 0.04], "Hide Trie")
    btn_theme  = _make_btn([0.50, 0.03, 0.14, 0.04], "Dark Mode")
    btn_legend = _make_btn([0.68, 0.03, 0.10, 0.04], "[ − ]")

    all_btns = [btn_prev, btn_next, btn_trie, btn_theme, btn_legend]

    def _refresh_btn_colors():
        T = THEMES[st["theme"]]
        for btn in all_btns:
            btn.color      = T["btn_bg"]
            btn.hovercolor = T["btn_hover"]
            btn.label.set_color(T["btn_fg"])
            btn.ax.set_facecolor(T["btn_bg"])

    def on_prev(event):
        if not steps:
            return
        st["step"] = max(0, st["step"] - 1)
        _, curr, _ = steps[st["step"]]
        st["active_node"] = curr
        redraw()

    def on_next(event):
        if not steps:
            return
        st["step"] = min(len(steps) - 1, st["step"] + 1)
        _, curr, _ = steps[st["step"]]
        st["active_node"] = curr
        redraw()

    def on_trie_toggle(event):
        st["trie_visible"] = not st["trie_visible"]
        btn_trie.label.set_text(
            "Hide Trie" if st["trie_visible"] else "Show Trie"
        )
        redraw()

    def on_theme_toggle(event):
        st["theme"] = "dark" if st["theme"] == "light" else "light"
        btn_theme.label.set_text(
            "Light Mode" if st["theme"] == "dark" else "Dark Mode"
        )
        _refresh_btn_colors()
        redraw()

    def on_legend_toggle(event):
        st["legend_visible"] = not st["legend_visible"]
        btn_legend.label.set_text(
            "[ − ]" if st["legend_visible"] else "[ + ]"
        )
        redraw()

    btn_prev.on_clicked(on_prev)
    btn_next.on_clicked(on_next)
    btn_trie.on_clicked(on_trie_toggle)
    btn_theme.on_clicked(on_theme_toggle)
    btn_legend.on_clicked(on_legend_toggle)

    # keyboard shortcuts
    def on_key(event):
        if event.key == "left":
            on_prev(None)
        elif event.key == "right":
            on_next(None)

    fig.canvas.mpl_connect("key_press_event", on_key)

    redraw()
    plt.show()