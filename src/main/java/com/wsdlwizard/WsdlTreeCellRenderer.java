package com.wsdlwizard;

import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.wsdl.Operation;
import javax.wsdl.Port;
import javax.wsdl.Service;
import java.awt.*;

public class WsdlTreeCellRenderer extends DefaultTreeCellRenderer {

    private final Icon serviceIcon;
    private final Icon portIcon;
    private final Icon operationIcon;

    public WsdlTreeCellRenderer() {
        // In a real extension, we'd load images. For now, we'll use UIManager icons or create simple ones.
        // Or just rely on text styling if icons aren't available.
        serviceIcon = UIManager.getIcon("FileView.computerIcon");
        portIcon = UIManager.getIcon("FileView.directoryIcon");
        operationIcon = UIManager.getIcon("FileView.fileIcon");
    }

    @Override
    public Component getTreeCellRendererComponent(JTree tree, Object value, boolean sel, boolean expanded, boolean leaf, int row, boolean hasFocus) {
        super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);

        if (value instanceof DefaultMutableTreeNode) {
            Object userObject = ((DefaultMutableTreeNode) value).getUserObject();
            if (userObject instanceof Service) {
                setIcon(serviceIcon);
                setText(((Service) userObject).getQName().getLocalPart());
                setFont(getFont().deriveFont(Font.BOLD));
            } else if (userObject instanceof Port) {
                setIcon(portIcon);
                setText(((Port) userObject).getName());
                setFont(getFont().deriveFont(Font.PLAIN));
            } else if (userObject instanceof Operation) {
                setIcon(operationIcon);
                setText(((Operation) userObject).getName());
                setFont(getFont().deriveFont(Font.PLAIN));
            }
        }

        return this;
    }
}
