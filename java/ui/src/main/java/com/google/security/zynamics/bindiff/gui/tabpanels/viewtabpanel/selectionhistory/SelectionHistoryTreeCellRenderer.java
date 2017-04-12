package com.google.security.zynamics.bindiff.gui.tabpanels.viewtabpanel.selectionhistory;

import com.google.common.base.Preconditions;
import com.google.security.zynamics.bindiff.graph.filter.GraphNodeFilter;
import com.google.security.zynamics.zylib.yfileswrap.gui.zygraph.AbstractZyGraph;
import com.google.security.zynamics.zylib.yfileswrap.gui.zygraph.nodes.ZyGraphNode;
import java.awt.Color;
import java.awt.Component;
import java.util.Collection;
import java.util.List;
import javax.swing.Icon;
import javax.swing.JTree;
import javax.swing.tree.DefaultTreeCellRenderer;

public class SelectionHistoryTreeCellRenderer extends DefaultTreeCellRenderer {
  private static final Color NORMAL_FONT_COLOR = new Color(0, 0, 0);
  private static final Color INVISIBLE_FONT_COLOR = new Color(128, 128, 128);
  private static final Color SELECTED_FONT_COLOR = new Color(160, 0, 0);
  private static final Color MIXED_STATE_GROUP_NODE_COLOR = new Color(160, 120, 120);

  private final AbstractZyGraph<?, ?> graph;

  public SelectionHistoryTreeCellRenderer(final AbstractZyGraph<?, ?> graph) {
    this.graph = Preconditions.checkNotNull(graph);
  }

  @Override
  public Component getTreeCellRendererComponent(
      final JTree tree,
      final Object value,
      final boolean selected,
      final boolean expanded,
      final boolean leaf,
      final int row,
      final boolean hasFocus) {
    setBackgroundSelectionColor(Color.WHITE);
    setBorderSelectionColor(Color.WHITE);

    super.getTreeCellRendererComponent(tree, value, selected, expanded, leaf, row, hasFocus);

    final Icon icon = ((AbstractSelectionHistoryTreeNode) value).getIcon();
    if (icon != null) {
      setIcon(icon);
    }

    final List<? extends ZyGraphNode<?>> selectedAndVisibleNodes =
        GraphNodeFilter.filterNodes(graph, GraphNodeFilter.Criterium.SELECTED_VISIBLE);

    final List<? extends ZyGraphNode<?>> invisibleNodes =
        GraphNodeFilter.filterNodes(graph, GraphNodeFilter.Criterium.INVISIBLE);

    setForeground(NORMAL_FONT_COLOR);

    if (value instanceof SelectionHistoryTreeGroupNode) {
      final SelectionHistoryTreeGroupNode treeNode = (SelectionHistoryTreeGroupNode) value;

      if (!treeNode.isRoot()) {
        int countAll = 0;
        int countVisbleSelected = 0;
        int countVisibleUnselected = 0;
        int countInvisible = 0;

        final Collection<ZyGraphNode<?>> nodes = treeNode.getSnapshot().getSelection();

        for (final ZyGraphNode<?> graphNode : nodes) {
          countAll++;

          if (graphNode.isVisible()) {
            if (graphNode.isSelected()) {
              countVisbleSelected++;
            } else {
              countVisibleUnselected++;
            }

          } else {
            countInvisible++;
          }
        }

        if (countAll == countVisbleSelected) {
          setForeground(SELECTED_FONT_COLOR);
        } else if (countAll == countVisibleUnselected) {
          setForeground(NORMAL_FONT_COLOR);
        } else if (countAll == countInvisible) {
          setForeground(INVISIBLE_FONT_COLOR);
        } else {
          setForeground(MIXED_STATE_GROUP_NODE_COLOR);
        }
      }
    } else if (value instanceof SelectionHistoryTreeNode) {
      final SelectionHistoryTreeNode treeNode = (SelectionHistoryTreeNode) value;

      final ZyGraphNode<?> graphNode = treeNode.getNode();

      if (selectedAndVisibleNodes.contains(graphNode)) {
        setForeground(SELECTED_FONT_COLOR);
      } else if (invisibleNodes.contains(graphNode)) {
        setForeground(INVISIBLE_FONT_COLOR);
      }
    }

    return this;
  }
}