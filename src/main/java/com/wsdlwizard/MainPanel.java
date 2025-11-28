
package com.wsdlwizard;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;
import javax.wsdl.*;
import java.awt.*;
import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MainPanel extends JPanel {

    private final MontoyaApi api;
    private final JTree wsdlTree;
    private final DefaultTreeModel treeModel;
    private final JTextArea documentationArea;
    private final JTextArea requestArea;
    private final JTextArea responseArea;
    private final JButton sendToRepeaterButton;
    private final JPanel parameterPanel;
    private final List<JTextField> parameterFields = new ArrayList<>();
    private final List<String> parameterNames = new ArrayList<>();
    private final JCheckBox followRedirectsCheckbox;
    
    private final FuzzerPanel fuzzerPanel;

    private Definition currentDefinition;
    private Port currentPort;
    private Operation currentOperation;

    public MainPanel(MontoyaApi api) {
        this.api = api;
        setLayout(new BorderLayout());

        // Toolbar
        JToolBar toolbar = new JToolBar();
        JButton loadFileButton = new JButton("Load WSDL File");
        loadFileButton.setBackground(new Color(229, 106, 23)); // Burp Orange
        loadFileButton.setForeground(Color.WHITE);
        loadFileButton.setOpaque(true);
        loadFileButton.setBorderPainted(false);
        loadFileButton.addActionListener(e -> loadWsdlFromFile());
        toolbar.add(loadFileButton);
        add(toolbar, BorderLayout.NORTH);

        // Tree
        DefaultMutableTreeNode root = new DefaultMutableTreeNode("WSDL Structure");
        treeModel = new DefaultTreeModel(root);
        wsdlTree = new JTree(treeModel);
        wsdlTree.setCellRenderer(new WsdlTreeCellRenderer());
        wsdlTree.addTreeSelectionListener(e -> onTreeSelection(e.getPath()));
        JScrollPane treeScroll = new JScrollPane(wsdlTree);
        treeScroll.setPreferredSize(new Dimension(250, 0));

        // Right Panel (Tabbed: Details, Fuzzer)
        JTabbedPane mainTabs = new JTabbedPane();

        // Details Tab
        JSplitPane detailsSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        


    // ... (constructor start)

        // Top: Documentation & Parameters
        JPanel topPanel = new JPanel(new BorderLayout());
        documentationArea = new JTextArea(3, 20);
        documentationArea.setEditable(false);
        documentationArea.setLineWrap(true);
        JScrollPane docScroll = new JScrollPane(documentationArea);
        docScroll.setBorder(BorderFactory.createTitledBorder("Documentation"));
        
        parameterPanel = new JPanel();
        parameterPanel.setLayout(new BoxLayout(parameterPanel, BoxLayout.Y_AXIS));
        JScrollPane paramScroll = new JScrollPane(parameterPanel);
        paramScroll.setBorder(BorderFactory.createTitledBorder("Parameters"));
        paramScroll.setPreferredSize(new Dimension(0, 150));

        JSplitPane topSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, docScroll, paramScroll);
        topSplit.setResizeWeight(0.5);
        topPanel.add(topSplit, BorderLayout.CENTER);
        detailsSplit.setTopComponent(topPanel);

        // Bottom: Request/Response
        JPanel bottomPanel = new JPanel(new BorderLayout());
        
        JPanel controlsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        sendToRepeaterButton = new JButton("Send to Repeater");
        sendToRepeaterButton.setEnabled(false);
        sendToRepeaterButton.addActionListener(e -> sendToRepeater());
        controlsPanel.add(sendToRepeaterButton);

        JButton executeButton = new JButton("Quick Execute");
        executeButton.addActionListener(e -> executeRequest());
        controlsPanel.add(executeButton);
        
        followRedirectsCheckbox = new JCheckBox("Follow Redirects");
        controlsPanel.add(followRedirectsCheckbox);
        
        bottomPanel.add(controlsPanel, BorderLayout.NORTH);

        JTabbedPane reqResTabs = new JTabbedPane();
        requestArea = new JTextArea();
        reqResTabs.addTab("Request", new JScrollPane(requestArea));
        responseArea = new JTextArea();
        reqResTabs.addTab("Response", new JScrollPane(responseArea));
        bottomPanel.add(reqResTabs, BorderLayout.CENTER);

        detailsSplit.setBottomComponent(bottomPanel);
        detailsSplit.setResizeWeight(0.3);

        mainTabs.addTab("Operation Details", detailsSplit);

        // Fuzzer Tab
        fuzzerPanel = new FuzzerPanel(api);
        mainTabs.addTab("WSDL Fuzzer", fuzzerPanel);

        // Main Split
        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, treeScroll, mainTabs);
        mainSplit.setResizeWeight(0.2);
        add(mainSplit, BorderLayout.CENTER);
    }

    private void loadWsdlFromFile() {
        JFileChooser fileChooser = new JFileChooser();
        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try {
                String content = Files.readString(file.toPath());
                loadWsdl(content);
            } catch (Exception e) {
                api.logging().logToError("Error loading file: " + e.getMessage());
                JOptionPane.showMessageDialog(this, "Error loading file: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    public void loadWsdl(String content) {
        try {
            currentDefinition = WsdlParser.parseWsdl(content);
            fuzzerPanel.setDefinition(currentDefinition);
            refreshTree();
            api.logging().logToOutput("WSDL loaded successfully.");
        } catch (Exception e) {
            api.logging().logToError("Error parsing WSDL: " + e.getMessage());
            JOptionPane.showMessageDialog(this, "Error parsing WSDL: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void refreshTree() {
        DefaultMutableTreeNode root = new DefaultMutableTreeNode("Services");
        Map services = currentDefinition.getServices();
        
        for (Object sKey : services.keySet()) {
            Service service = (Service) services.get(sKey);
            DefaultMutableTreeNode serviceNode = new DefaultMutableTreeNode(service);
            root.add(serviceNode);

            Map ports = service.getPorts();
            for (Object pKey : ports.keySet()) {
                Port port = (Port) ports.get(pKey);
                DefaultMutableTreeNode portNode = new DefaultMutableTreeNode(port);
                serviceNode.add(portNode);

                Binding binding = port.getBinding();
                if (binding != null) {
                    List operations = binding.getPortType().getOperations();
                    for (Object op : operations) {
                        Operation operation = (Operation) op;
                        DefaultMutableTreeNode opNode = new DefaultMutableTreeNode(operation);
                        portNode.add(opNode);
                    }
                }
            }
        }
        treeModel.setRoot(root);
        treeModel.reload();
        expandAllNodes(wsdlTree, 0, wsdlTree.getRowCount());
    }

    private void expandAllNodes(JTree tree, int startingIndex, int rowCount) {
        for (int i = startingIndex; i < rowCount; ++i) {
            tree.expandRow(i);
        }
        if (tree.getRowCount() != rowCount) {
            expandAllNodes(tree, rowCount, tree.getRowCount());
        }
    }

    private void onTreeSelection(TreePath path) {
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
        Object userObject = node.getUserObject();

        if (userObject instanceof Operation) {
            currentOperation = (Operation) userObject;
            DefaultMutableTreeNode parent = (DefaultMutableTreeNode) node.getParent();
            if (parent.getUserObject() instanceof Port) {
                currentPort = (Port) parent.getUserObject();
            }

            documentationArea.setText(WsdlParser.getDocumentation(currentOperation));
            
            // Populate Parameter Form
            parameterPanel.removeAll();
            parameterFields.clear();
            parameterNames.clear();
            
            List<String> params = WsdlParser.getParameters(currentOperation);
            for (String param : params) {
                JPanel row = new JPanel(new BorderLayout());
                row.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
                JLabel label = new JLabel(param + ": ");
                label.setPreferredSize(new Dimension(100, 25));
                JTextField field = new JTextField();
                field.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
                    public void insertUpdate(javax.swing.event.DocumentEvent e) { generateRequestFromForm(); }
                    public void removeUpdate(javax.swing.event.DocumentEvent e) { generateRequestFromForm(); }
                    public void changedUpdate(javax.swing.event.DocumentEvent e) { generateRequestFromForm(); }
                });
                
                row.add(label, BorderLayout.WEST);
                row.add(field, BorderLayout.CENTER);
                parameterPanel.add(row);
                
                parameterFields.add(field);
                parameterNames.add(param);
            }
            parameterPanel.revalidate();
            parameterPanel.repaint();
            
            generateRequestFromForm();
            sendToRepeaterButton.setEnabled(true);
        } else {
            currentOperation = null;
            currentPort = null;
            sendToRepeaterButton.setEnabled(false);
            documentationArea.setText("");
            requestArea.setText("");
            parameterPanel.removeAll();
            parameterPanel.revalidate();
            parameterPanel.repaint();
        }
    }

    private void generateRequestFromForm() {
        if (currentOperation != null && currentDefinition != null) {
            Map<String, String> values = new HashMap<>();
            for (int i = 0; i < parameterNames.size(); i++) {
                String val = parameterFields.get(i).getText();
                if (val != null && !val.isEmpty()) {
                    values.put(parameterNames.get(i), val);
                }
            }
            requestArea.setText(WsdlParser.generateSoapRequest(currentOperation, currentDefinition.getTargetNamespace(), values));
        }
    }

    private void executeRequest() {
        if (currentPort != null && currentOperation != null) {
            String endpoint = WsdlParser.getEndpointUrl(currentPort);
            if (endpoint == null) {
                api.logging().logToError("Endpoint URL not found for port: " + currentPort.getName());
                JOptionPane.showMessageDialog(this, "Could not determine endpoint URL for this port.", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }

            String requestBody = requestArea.getText();
            // Run in background thread
            new Thread(() -> {
                try {
                    HttpRequest request = HttpRequest.httpRequestFromUrl(endpoint)
                            .withMethod("POST")
                            .withHeader("Content-Type", "text/xml;charset=UTF-8")
                            .withHeader("SOAPAction", "") 
                            .withBody(requestBody);

                    HttpResponse response = api.http().sendRequest(request).response();
                    
                    // Simple redirect following (max 5)
                    if (followRedirectsCheckbox.isSelected()) {
                        int redirects = 0;
                        while (redirects < 5 && (response.statusCode() >= 300 && response.statusCode() < 400)) {
                            String location = response.headerValue("Location");
                            if (location != null && !location.isEmpty()) {
                                request = HttpRequest.httpRequestFromUrl(location)
                                        .withMethod("POST") // Keep POST for SOAP usually, or switch to GET? SOAP usually stays POST but redirects are rare for SOAP. 
                                        // Actually, 307/308 preserve method, 301/302 might switch to GET. 
                                        // For WSDL testing, if we get a redirect, it's likely a moved endpoint.
                                        // Let's assume we keep the body and method for now or just follow the new URL.
                                        // Safest to just update URL and keep body.
                                        .withHeader("Content-Type", "text/xml;charset=UTF-8")
                                        .withHeader("SOAPAction", "")
                                        .withBody(requestBody);
                                response = api.http().sendRequest(request).response();
                                redirects++;
                            } else {
                                break;
                            }
                        }
                    }

                    HttpResponse finalResponse = response;
                    SwingUtilities.invokeLater(() -> {
                        responseArea.setText(finalResponse.toString());
                    });
                } catch (Exception e) {
                    api.logging().logToError("Error executing request: " + e.getMessage());
                    SwingUtilities.invokeLater(() -> {
                        JOptionPane.showMessageDialog(this, "Error executing request: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                    });
                }
            }).start();
        }
    }

    private void sendToRepeater() {
        if (currentPort != null && currentOperation != null) {
            String endpoint = WsdlParser.getEndpointUrl(currentPort);
            if (endpoint == null) {
                api.logging().logToError("Endpoint URL not found for port: " + currentPort.getName());
                JOptionPane.showMessageDialog(this, "Could not determine endpoint URL for this port.", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }

            String requestBody = requestArea.getText();
            try {
                HttpRequest request = HttpRequest.httpRequestFromUrl(endpoint)
                        .withMethod("POST")
                        .withHeader("Content-Type", "text/xml;charset=UTF-8")
                        .withHeader("SOAPAction", "")
                        .withBody(requestBody);

                api.repeater().sendToRepeater(request, "WSDL Raider: " + currentOperation.getName());
                api.logging().logToOutput("Sent to Repeater: " + currentOperation.getName());
            } catch (Exception e) {
                api.logging().logToError("Error sending to Repeater: " + e.getMessage());
                JOptionPane.showMessageDialog(this, "Error sending to Repeater: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
}

