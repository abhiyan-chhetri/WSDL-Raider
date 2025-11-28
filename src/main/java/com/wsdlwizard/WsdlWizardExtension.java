package com.wsdlwizard;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.UserInterface;

public class WsdlWizardExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("WSDL Raider");

        // Initialize the main UI panel
        MainPanel mainPanel = new MainPanel(api);

        // Register the main tab
        api.userInterface().registerSuiteTab("WSDL Raider", mainPanel);

        // Register context menu items
        api.userInterface().registerContextMenuItemsProvider(new ContextMenu(api, mainPanel));

        api.logging().logToOutput("WSDL Raider loaded successfully.");
    }
}
