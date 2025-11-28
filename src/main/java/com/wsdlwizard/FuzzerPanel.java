package com.wsdlwizard;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.wsdl.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class FuzzerPanel extends JPanel {

    private final MontoyaApi api;
    private Definition currentDefinition;
    
    private final JComboBox<String> attackTypeSelector;
    private final JComboBox<String> parameterSelector;
    private final JTextArea payloadArea;
    private final JCheckBox scopeAllCheckbox;
    private final JTable resultsTable;
    private final DefaultTableModel resultsModel;
    private final JButton startButton;
    private final JButton stopButton;
    private final JLabel statusLabel;
    private final JButton loadPayloadsButton;
    private final JButton pastePayloadsButton;
    private final JCheckBox followRedirectsCheckbox;
    
    private final JTextArea requestViewer;
    private final JTextArea responseViewer;
    
    private volatile boolean isRunning = false;
    private ExecutorService executor;
    private final List<FuzzResult> allFuzzResults = new ArrayList<>();
    private final List<FuzzResult> displayedResults = new ArrayList<>();

    private static class FuzzResult {
        String operation;
        String parameter;
        String payload;
        int status;
        int length;
        HttpRequest request;
        HttpResponse response;

        public FuzzResult(String operation, String parameter, String payload, int status, int length, HttpRequest request, HttpResponse response) {
            this.operation = operation;
            this.parameter = parameter;
            this.payload = payload;
            this.status = status;
            this.length = length;
            this.request = request;
            this.response = response;
        }
    }

    public FuzzerPanel(MontoyaApi api) {
        this.api = api;
        setLayout(new BorderLayout());

        // Configuration Panel
        JPanel configPanel = new JPanel(new GridBagLayout());
        configPanel.setBorder(BorderFactory.createTitledBorder("Fuzzer Configuration"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Scope
        gbc.gridx = 0; gbc.gridy = 0;
        configPanel.add(new JLabel("Scope:"), gbc);
        scopeAllCheckbox = new JCheckBox("All Operations", true);
        gbc.gridx = 1;
        configPanel.add(scopeAllCheckbox, gbc);

        // Parameter Selector
        gbc.gridx = 0; gbc.gridy = 1;
        configPanel.add(new JLabel("Target Parameter:"), gbc);
        parameterSelector = new JComboBox<>();
        parameterSelector.addItem("All Parameters");
        gbc.gridx = 1;
        configPanel.add(parameterSelector, gbc);

        // Attack Type
        gbc.gridx = 0; gbc.gridy = 2;
        configPanel.add(new JLabel("Attack Type:"), gbc);
        attackTypeSelector = new JComboBox<>(new String[]{"SQL Injection", "XSS", "XXE", "Overflow", "Format String"});
        attackTypeSelector.addActionListener(e -> updatePayloads());
        gbc.gridx = 1;
        configPanel.add(attackTypeSelector, gbc);

        // Payloads
        gbc.gridx = 0; gbc.gridy = 3; gbc.anchor = GridBagConstraints.NORTHWEST;
        configPanel.add(new JLabel("Payloads (1 per line):"), gbc);
        payloadArea = new JTextArea(5, 20);
        gbc.gridx = 1; gbc.weightx = 1.0; gbc.weighty = 1.0; gbc.fill = GridBagConstraints.BOTH;
        configPanel.add(new JScrollPane(payloadArea), gbc);
        
        // Payload Buttons
        JPanel payloadButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        loadPayloadsButton = new JButton("Load");
        loadPayloadsButton.addActionListener(e -> loadPayloadsFromFile());
        pastePayloadsButton = new JButton("Paste");
        pastePayloadsButton.addActionListener(e -> pastePayloadsFromClipboard());
        payloadButtonPanel.add(loadPayloadsButton);
        payloadButtonPanel.add(pastePayloadsButton);
        
        gbc.gridx = 1; gbc.gridy = 4; gbc.weighty = 0; gbc.fill = GridBagConstraints.HORIZONTAL;
        configPanel.add(payloadButtonPanel, gbc);
        
        updatePayloads(); // Init payloads

        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        statusLabel = new JLabel("Status: Idle");
        statusLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 10));
        buttonPanel.add(statusLabel);
        
        followRedirectsCheckbox = new JCheckBox("Follow Redirects");
        buttonPanel.add(followRedirectsCheckbox);
        
        startButton = new JButton("Start Fuzzing");
        startButton.addActionListener(e -> startFuzzing());
        stopButton = new JButton("Stop");
        stopButton.setEnabled(false);
        stopButton.addActionListener(e -> stopFuzzing());
        buttonPanel.add(startButton);
        buttonPanel.add(stopButton);

        gbc.gridx = 0; gbc.gridy = 5; gbc.gridwidth = 2; gbc.weighty = 0; gbc.fill = GridBagConstraints.HORIZONTAL;
        configPanel.add(buttonPanel, gbc);

        // Results Panel
        JPanel resultsPanel = new JPanel(new BorderLayout());
        
        // Search Bar
        JPanel searchPanel = new JPanel(new BorderLayout());
        searchPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        searchPanel.add(new JLabel("Search Response: "), BorderLayout.WEST);
        JTextField searchField = new JTextField();
        searchField.addActionListener(e -> filterResults(searchField.getText()));
        searchPanel.add(searchField, BorderLayout.CENTER);
        JButton searchButton = new JButton("Search");
        searchButton.addActionListener(e -> filterResults(searchField.getText()));
        searchPanel.add(searchButton, BorderLayout.EAST);
        resultsPanel.add(searchPanel, BorderLayout.NORTH);

        // Table
        resultsModel = new DefaultTableModel(new String[]{"Operation", "Parameter", "Payload", "Status", "Length"}, 0) {
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex == 3 || columnIndex == 4) {
                    return Integer.class;
                }
                return String.class;
            }
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        resultsTable = new JTable(resultsModel);
        resultsTable.setAutoCreateRowSorter(true);
        JScrollPane resultsScroll = new JScrollPane(resultsTable);
        resultsPanel.add(resultsScroll, BorderLayout.CENTER);
        
        // Viewer Panel
        JSplitPane viewerSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        requestViewer = new JTextArea();
        JScrollPane requestScroll = new JScrollPane(requestViewer);
        requestScroll.setBorder(BorderFactory.createTitledBorder("Request"));
        
        responseViewer = new JTextArea();
        JScrollPane responseScroll = new JScrollPane(responseViewer);
        responseScroll.setBorder(BorderFactory.createTitledBorder("Response"));
        
        viewerSplit.setTopComponent(requestScroll);
        viewerSplit.setBottomComponent(responseScroll);
        viewerSplit.setResizeWeight(0.5);
        
        // Add listener after viewers are initialized
        resultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int viewRow = resultsTable.getSelectedRow();
                if (viewRow >= 0) {
                    int modelRow = resultsTable.convertRowIndexToModel(viewRow);
                    if (modelRow < displayedResults.size()) {
                        FuzzResult result = displayedResults.get(modelRow);
                        requestViewer.setText(result.request.toString());
                        responseViewer.setText(result.response.toString());
                        // Scroll to top
                        requestViewer.setCaretPosition(0);
                        responseViewer.setCaretPosition(0);
                    }
                }
            }
        });
        
        // Context Menu for Table
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem sendToRepeaterItem = new JMenuItem("Send to Repeater");
        sendToRepeaterItem.addActionListener(e -> {
            int viewRow = resultsTable.getSelectedRow();
            if (viewRow >= 0) {
                int modelRow = resultsTable.convertRowIndexToModel(viewRow);
                if (modelRow < displayedResults.size()) {
                    FuzzResult result = displayedResults.get(modelRow);
                    api.repeater().sendToRepeater(result.request, "Fuzz: " + result.operation);
                }
            }
        });
        popupMenu.add(sendToRepeaterItem);
        resultsTable.setComponentPopupMenu(popupMenu);
        
        // Context Menu for Viewers
        JPopupMenu viewerPopupMenu = new JPopupMenu();
        JMenuItem viewerSendToRepeaterItem = new JMenuItem("Send to Repeater");
        viewerSendToRepeaterItem.addActionListener(e -> {
            int viewRow = resultsTable.getSelectedRow();
            if (viewRow >= 0) {
                int modelRow = resultsTable.convertRowIndexToModel(viewRow);
                if (modelRow < displayedResults.size()) {
                    FuzzResult result = displayedResults.get(modelRow);
                    api.repeater().sendToRepeater(result.request, "Fuzz: " + result.operation);
                }
            }
        });
        viewerPopupMenu.add(viewerSendToRepeaterItem);
        requestViewer.setComponentPopupMenu(viewerPopupMenu);
        responseViewer.setComponentPopupMenu(viewerPopupMenu);
        
        // Main Split
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplit.setTopComponent(configPanel);
        
        JSplitPane contentSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        contentSplit.setLeftComponent(resultsPanel);
        contentSplit.setRightComponent(viewerSplit);
        contentSplit.setResizeWeight(0.6);
        
        mainSplit.setBottomComponent(contentSplit);
        add(mainSplit, BorderLayout.CENTER);

    }

    public void setDefinition(Definition definition) {
        this.currentDefinition = definition;
        updateParameterList();
    }

    private void updateParameterList() {
        parameterSelector.removeAllItems();
        parameterSelector.addItem("All Parameters");
        
        if (currentDefinition != null) {
            List<String> allParams = new ArrayList<>();
            Map services = currentDefinition.getServices();
            for (Object sKey : services.keySet()) {
                Service service = (Service) services.get(sKey);
                for (Object pKey : service.getPorts().keySet()) {
                    Port port = (Port) service.getPorts().get(pKey);
                    Binding binding = port.getBinding();
                    if (binding == null) continue;
                    for (Object op : binding.getPortType().getOperations()) {
                        Operation operation = (Operation) op;
                        List<String> params = WsdlParser.getParameters(operation);
                        for (String p : params) {
                            if (!allParams.contains(p)) {
                                allParams.add(p);
                            }
                        }
                    }
                }
            }
            // Sort and add
            allParams.stream().sorted().forEach(parameterSelector::addItem);
        }
    }

    private void updatePayloads() {
        String type = (String) attackTypeSelector.getSelectedItem();
        if ("SQL Injection".equals(type)) {
            payloadArea.setText("' OR '1'='1\n' OR 1=1--\nadmin' --\n' UNION SELECT 1,2,3--");
        } else if ("XSS".equals(type)) {
            payloadArea.setText("\"><script>alert(1)</script>\n<img src=x onerror=alert(1)>");
        } else if ("XXE".equals(type)) {
            payloadArea.setText("<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\" > ]>&xxe;");
        } else if ("Overflow".equals(type)) {
            payloadArea.setText("A".repeat(1000));
        } else if ("Format String".equals(type)) {
            payloadArea.setText("%s%s%s%s\n%x%x%x%x");
        } else {
            payloadArea.setText("");
        }
    }

    private void loadPayloadsFromFile() {
        JFileChooser fileChooser = new JFileChooser();
        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                String content = java.nio.file.Files.readString(fileChooser.getSelectedFile().toPath());
                payloadArea.setText(content);
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, "Error loading file: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void pastePayloadsFromClipboard() {
        try {
            String data = (String) Toolkit.getDefaultToolkit().getSystemClipboard().getData(java.awt.datatransfer.DataFlavor.stringFlavor);
            if (data != null) {
                payloadArea.setText(data);
            }
        } catch (Exception e) {
            // Ignore
        }
    }
    
    private void filterResults(String query) {
        displayedResults.clear();
        resultsModel.setRowCount(0);
        
        String lowerQuery = query.toLowerCase();
        
        for (FuzzResult result : allFuzzResults) {
            if (query.isEmpty() || result.response.toString().toLowerCase().contains(lowerQuery)) {
                displayedResults.add(result);
                resultsModel.addRow(new Object[]{result.operation, result.parameter, result.payload, result.status, result.length});
            }
        }
    }

    private void startFuzzing() {
        if (currentDefinition == null) {
            JOptionPane.showMessageDialog(this, "No WSDL loaded.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        isRunning = true;
        startButton.setEnabled(false);
        stopButton.setEnabled(true);
        statusLabel.setText("Status: Running...");
        statusLabel.setForeground(new Color(229, 106, 23)); // Burp Orange
        
        resultsModel.setRowCount(0);
        allFuzzResults.clear();
        displayedResults.clear();
        requestViewer.setText("");
        responseViewer.setText("");
        
        executor = Executors.newFixedThreadPool(5); // 5 threads

        String[] payloads = payloadArea.getText().split("\\n");
        String selectedParam = (String) parameterSelector.getSelectedItem();
        boolean fuzzAllParams = "All Parameters".equals(selectedParam);
        boolean followRedirects = followRedirectsCheckbox.isSelected();

        // Logic to iterate operations and submit tasks
        new Thread(() -> {
            try {
                Map services = currentDefinition.getServices();
                for (Object sKey : services.keySet()) {
                    Service service = (Service) services.get(sKey);
                    for (Object pKey : service.getPorts().keySet()) {
                        Port port = (Port) service.getPorts().get(pKey);
                        String endpoint = WsdlParser.getEndpointUrl(port);
                        
                        if (endpoint == null) {
                            api.logging().logToError("Skipping port " + port.getName() + ": No endpoint URL found.");
                            continue;
                        }
                        
                        Binding binding = port.getBinding();
                        if (binding == null) continue;

                        for (Object op : binding.getPortType().getOperations()) {
                            if (!isRunning) break;
                            Operation operation = (Operation) op;
                            
                            // Check Scope
                            if (!scopeAllCheckbox.isSelected()) {
                                // TODO: Implement specific operation selection if needed
                            }

                            List<String> params = WsdlParser.getParameters(operation);
                            
                            for (String param : params) {
                                if (!fuzzAllParams && !param.equals(selectedParam)) continue;

                                for (String payload : payloads) {
                                    if (!isRunning) break;
                                    if (payload.trim().isEmpty()) continue;

                                    executor.submit(() -> {
                                        try {
                                            Map<String, String> values = new HashMap<>();
                                            values.put(param, payload);
                                            String soapBody = WsdlParser.generateSoapRequest(operation, currentDefinition.getTargetNamespace(), values);
                                            
                                            HttpRequest request = HttpRequest.httpRequestFromUrl(endpoint)
                                                    .withMethod("POST")
                                                    .withHeader("Content-Type", "text/xml;charset=UTF-8")
                                                    .withHeader("SOAPAction", "")
                                                    .withBody(soapBody);

                                            HttpResponse response = api.http().sendRequest(request).response();
                                            
                                            // Redirects
                                            if (followRedirects) {
                                                int redirects = 0;
                                                while (redirects < 5 && (response.statusCode() >= 300 && response.statusCode() < 400)) {
                                                    String location = response.headerValue("Location");
                                                    if (location != null && !location.isEmpty()) {
                                                        request = HttpRequest.httpRequestFromUrl(location)
                                                                .withMethod("POST")
                                                                .withHeader("Content-Type", "text/xml;charset=UTF-8")
                                                                .withHeader("SOAPAction", "")
                                                                .withBody(soapBody);
                                                        response = api.http().sendRequest(request).response();
                                                        redirects++;
                                                    } else {
                                                        break;
                                                    }
                                                }
                                            }

                                            HttpResponse finalResponse = response;
                                            HttpRequest finalRequest = request;
                                            SwingUtilities.invokeLater(() -> {
                                                if (!isRunning) return;
                                                FuzzResult result = new FuzzResult(operation.getName(), param, payload, finalResponse.statusCode(), finalResponse.body().length(), finalRequest, finalResponse);
                                                allFuzzResults.add(result);
                                                // Add to display if matches current filter (empty filter for now during run)
                                                // For performance, maybe don't filter during run? Or just assume empty.
                                                // Let's assume empty filter during run for simplicity or check if we want to support live filtering.
                                                // Live filtering might be slow. Let's just add to displayedResults.
                                                displayedResults.add(result);
                                                resultsModel.addRow(new Object[]{result.operation, result.parameter, result.payload, result.status, result.length});
                                            });
                                        } catch (Exception e) {
                                            api.logging().logToError("Fuzzer task error: " + e.getMessage());
                                        }
                                    });
                                }
                            }
                        }
                    }
                }
                
                // Wait for completion
                executor.shutdown();
                try {
                    if (executor.awaitTermination(1, java.util.concurrent.TimeUnit.HOURS)) {
                         SwingUtilities.invokeLater(() -> {
                            if (isRunning) { // Only if not manually stopped
                                statusLabel.setText("Status: Finished");
                                statusLabel.setForeground(new Color(0, 128, 0)); // Green
                                startButton.setEnabled(true);
                                stopButton.setEnabled(false);
                                isRunning = false;
                            }
                        });
                    }
                } catch (InterruptedException e) {
                    // Ignore
                }

            } catch (Exception e) {
                api.logging().logToError("Fuzzer loop error: " + e.getMessage());
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("Status: Error");
                    statusLabel.setForeground(Color.RED);
                    JOptionPane.showMessageDialog(this, "Fuzzer error: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                });
            }
        }).start();
    }

    private void stopFuzzing() {
        isRunning = false;
        if (executor != null) {
            executor.shutdownNow();
        }
        startButton.setEnabled(true);
        stopButton.setEnabled(false);
        statusLabel.setText("Status: Stopped");
        statusLabel.setForeground(Color.RED);
    }
}
