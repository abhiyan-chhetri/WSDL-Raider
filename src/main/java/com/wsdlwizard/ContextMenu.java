package com.wsdlwizard;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class ContextMenu implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final MainPanel mainPanel;

    public ContextMenu(MontoyaApi api, MainPanel mainPanel) {
        this.api = api;
        this.mainPanel = mainPanel;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();

        JMenuItem parseWsdlItem = new JMenuItem("Parse WSDL");
        parseWsdlItem.addActionListener(e -> {
            String wsdlContent = extractWsdlContent(event);
            if (wsdlContent != null && !wsdlContent.isEmpty()) {
                mainPanel.loadWsdl(wsdlContent);
                // Switch to the WSDL Raider tab? 
                // Montoya doesn't have a direct API to switch tabs easily, 
                // but we can notify the user or just let them switch.
                // For now, we just load it.
                api.logging().logToOutput("WSDL loaded from context menu.");
            } else {
                JOptionPane.showMessageDialog(null, "No WSDL content found in selection.", "Error", JOptionPane.ERROR_MESSAGE);
            }
        });

        menuItems.add(parseWsdlItem);
        return menuItems;
    }

    private String extractWsdlContent(ContextMenuEvent event) {
        // Check for message editor context (e.g. Repeater/Proxy editor)
        if (event.messageEditorRequestResponse().isPresent()) {
            MessageEditorHttpRequestResponse editor = event.messageEditorRequestResponse().get();
            // Prefer response if available
            if (editor.selectionContext() == MessageEditorHttpRequestResponse.SelectionContext.RESPONSE) {
                return editor.requestResponse().response().toString();
            } else if (editor.selectionContext() == MessageEditorHttpRequestResponse.SelectionContext.REQUEST) {
                return editor.requestResponse().request().toString();
            }
        }

        // Check for selected request/responses (e.g. Proxy history, Target)
        if (!event.selectedRequestResponses().isEmpty()) {
            HttpRequestResponse rr = event.selectedRequestResponses().get(0);
            if (rr.response() != null) {
                return rr.response().toString();
            } else {
                return rr.request().toString();
            }
        }

        return null;
    }
}
