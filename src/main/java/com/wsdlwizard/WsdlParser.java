package com.wsdlwizard;

import javax.wsdl.*;
import javax.wsdl.extensions.ExtensibilityElement;
import javax.wsdl.extensions.schema.Schema;
import javax.wsdl.factory.WSDLFactory;
import javax.wsdl.xml.WSDLReader;
import javax.xml.namespace.QName;
import java.io.StringReader;
import java.util.*;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

public class WsdlParser {

    public static Definition parseWsdl(String wsdlContent) throws WSDLException {
        WSDLFactory factory = WSDLFactory.newInstance();
        WSDLReader reader = factory.newWSDLReader();
        reader.setFeature("javax.wsdl.verbose", false);
        reader.setFeature("javax.wsdl.importDocuments", true);
        try {
            return reader.readWSDL(null, new InputSource(new StringReader(wsdlContent)));
        } catch (WSDLException e) {
            // Fallback 1: Try to extract and complete embedded WSDL from SoapUI project
            java.util.regex.Pattern contentPattern = java.util.regex.Pattern.compile("<con:content>\\s*<!\\[CDATA\\[(.*?)\\]\\]>\\s*</con:content>", java.util.regex.Pattern.DOTALL);
            java.util.regex.Matcher contentMatcher = contentPattern.matcher(wsdlContent);
            if (contentMatcher.find()) {
                String embeddedWsdl = contentMatcher.group(1).trim();
                System.out.println("Found embedded WSDL content in SoapUI project.");
                
                // Try to parse as-is first
                try {
                    return reader.readWSDL(null, new InputSource(new StringReader(embeddedWsdl)));
                } catch (WSDLException ex) {
                    System.out.println("Embedded WSDL incomplete, attempting to synthesize missing sections...");
                    
                    // Extract endpoint from <con:endpoint> tag
                    java.util.regex.Pattern endpointPattern = java.util.regex.Pattern.compile("<con:endpoint>([^<]+)</con:endpoint>");
                    java.util.regex.Matcher endpointMatcher = endpointPattern.matcher(wsdlContent);
                    String endpoint = endpointMatcher.find() ? endpointMatcher.group(1) : "http://localhost/service";
                    
                    // Complete the WSDL by adding binding and service sections
                    String completedWsdl = synthesizeCompleteWsdl(embeddedWsdl, endpoint);
                    try {
                        return reader.readWSDL(null, new InputSource(new StringReader(completedWsdl)));
                    } catch (WSDLException ex2) {
                        System.out.println("Failed to parse synthesized WSDL: " + ex2.getMessage());
                    }
                }
            }

            // Fallback 2: Try to find a WSDL URL in the content
            java.util.regex.Pattern urlPattern = java.util.regex.Pattern.compile("(https?://[^\\s\"'<>]+(?:\\.wsdl|\\?WSDL|\\?wsdl))", java.util.regex.Pattern.CASE_INSENSITIVE);
            java.util.regex.Matcher urlMatcher = urlPattern.matcher(wsdlContent);
            if (urlMatcher.find()) {
                String wsdlUrl = urlMatcher.group(1);
                System.out.println("Found potential WSDL URL in content: " + wsdlUrl);
                return parseWsdlFromUrl(wsdlUrl);
            }
            throw e;
        }
    }

    private static String synthesizeCompleteWsdl(String incompleteWsdl, String endpoint) {
        // Check if binding and service already exist
        if (incompleteWsdl.contains("<wsdl:binding") && incompleteWsdl.contains("<wsdl:service")) {
            return incompleteWsdl;
        }
        
        // Extract portType name
        java.util.regex.Pattern portTypePattern = java.util.regex.Pattern.compile("<wsdl:portType\\s+name=\"([^\"]+)\"");
        java.util.regex.Matcher portTypeMatcher = portTypePattern.matcher(incompleteWsdl);
        String portTypeName = portTypeMatcher.find() ? portTypeMatcher.group(1) : "ServicePortType";
        
        // Extract targetNamespace
        java.util.regex.Pattern nsPattern = java.util.regex.Pattern.compile("targetNamespace=\"([^\"]+)\"");
        java.util.regex.Matcher nsMatcher = nsPattern.matcher(incompleteWsdl);
        String targetNs = nsMatcher.find() ? nsMatcher.group(1) : "http://tempuri.org/";
        
        // Find the closing </wsdl:definitions> tag
        int closingIndex = incompleteWsdl.lastIndexOf("</wsdl:definitions>");
        if (closingIndex == -1) {
            return incompleteWsdl; // Can't synthesize without proper structure
        }
        
        // Build binding and service sections
        StringBuilder binding = new StringBuilder();
        binding.append("\n    <wsdl:binding name=\"").append(portTypeName).append("Binding\" type=\"tns:").append(portTypeName).append("\">\n");
        binding.append("        <soap:binding style=\"document\" transport=\"http://schemas.xmlsoap.org/soap/http\"/>\n");
        
        // Extract operations and add them to binding
        java.util.regex.Pattern opPattern = java.util.regex.Pattern.compile("<wsdl:operation\\s+name=\"([^\"]+)\"");
        java.util.regex.Matcher opMatcher = opPattern.matcher(incompleteWsdl);
        while (opMatcher.find()) {
            String opName = opMatcher.group(1);
            binding.append("        <wsdl:operation name=\"").append(opName).append("\">\n");
            binding.append("            <soap:operation soapAction=\"\"/>\n");
            binding.append("            <wsdl:input><soap:body use=\"literal\"/></wsdl:input>\n");
            binding.append("            <wsdl:output><soap:body use=\"literal\"/></wsdl:output>\n");
            binding.append("        </wsdl:operation>\n");
        }
        binding.append("    </wsdl:binding>\n");
        
        // Build service section
        StringBuilder service = new StringBuilder();
        service.append("\n    <wsdl:service name=\"").append(portTypeName.replace("PortType", "Service")).append("\">\n");
        service.append("        <wsdl:port name=\"").append(portTypeName.replace("PortType", "Port")).append("\" binding=\"tns:").append(portTypeName).append("Binding\">\n");
        service.append("            <soap:address location=\"").append(endpoint).append("\"/>\n");
        service.append("        </wsdl:port>\n");
        service.append("    </wsdl:service>\n");
        
        // Add SOAP namespace if not present
        String result = incompleteWsdl;
        if (!result.contains("xmlns:soap=")) {
            result = result.replaceFirst("<wsdl:definitions", "<wsdl:definitions xmlns:soap=\"http://schemas.xmlsoap.org/wsdl/soap/\"");
        }
        
        // Insert binding and service before closing tag
        result = result.substring(0, closingIndex) + binding.toString() + service.toString() + result.substring(closingIndex);
        
        return result;
    }

    public static Definition parseWsdlFromUrl(String url) throws WSDLException {
        WSDLFactory factory = WSDLFactory.newInstance();
        WSDLReader reader = factory.newWSDLReader();
        reader.setFeature("javax.wsdl.verbose", false);
        reader.setFeature("javax.wsdl.importDocuments", true);
        return reader.readWSDL(url);
    }

    public enum AttackType {
        NORMAL, SQLI, XSS, XXE, OVERFLOW
    }

    public static List<String> getParameters(Definition definition, Operation operation) {
        List<String> params = new ArrayList<>();
        Input input = operation.getInput();
        if (input != null && input.getMessage() != null) {
            Map parts = input.getMessage().getParts();
            for (Object key : parts.keySet()) {
                Part part = (Part) parts.get(key);
                QName typeName = part.getTypeName();
                if (typeName != null) {
                    // Try to find complex type definition
                    List<String> complexParams = getComplexTypeParameters(definition, typeName);
                    if (!complexParams.isEmpty()) {
                        params.addAll(complexParams);
                    } else {
                        params.add(part.getName());
                    }
                } else {
                     // Element reference?
                     QName elementName = part.getElementName();
                     if (elementName != null) {
                         List<String> elementParams = getElementParameters(definition, elementName);
                         if (!elementParams.isEmpty()) {
                             params.addAll(elementParams);
                         } else {
                             params.add(part.getName());
                         }
                     } else {
                         params.add(part.getName());
                     }
                }
            }
        }
        return params;
    }

    private static List<String> getComplexTypeParameters(Definition definition, QName typeName) {
        List<String> params = new ArrayList<>();
        if (definition.getTypes() == null) return params;
        
        for (Object ext : definition.getTypes().getExtensibilityElements()) {
            if (ext instanceof Schema) {
                Schema schema = (Schema) ext;
                Element schemaElement = schema.getElement();
                if (schemaElement == null) continue;
                
                // Naive DOM traversal to find complexType or element
                // Note: Real world WSDLs can be very complex (imports, includes). This is a best-effort.
                NodeList complexTypes = schemaElement.getElementsByTagNameNS("*", "complexType");
                for (int i = 0; i < complexTypes.getLength(); i++) {
                    Element ct = (Element) complexTypes.item(i);
                    String name = ct.getAttribute("name");
                    if (name != null && name.equals(typeName.getLocalPart())) {
                        // Found the type, look for sequence/all -> element
                        extractElementsFromComplexType(ct, params);
                        return params;
                    }
                }
            }
        }
        return params;
    }

    private static List<String> getElementParameters(Definition definition, QName elementName) {
        List<String> params = new ArrayList<>();
        if (definition.getTypes() == null) return params;

        for (Object ext : definition.getTypes().getExtensibilityElements()) {
            if (ext instanceof Schema) {
                Schema schema = (Schema) ext;
                Element schemaElement = schema.getElement();
                if (schemaElement == null) continue;

                NodeList elements = schemaElement.getElementsByTagNameNS("*", "element");
                for (int i = 0; i < elements.getLength(); i++) {
                    Element el = (Element) elements.item(i);
                    String name = el.getAttribute("name");
                    if (name != null && name.equals(elementName.getLocalPart())) {
                        // Check if it has inline complexType
                        NodeList complexTypes = el.getElementsByTagNameNS("*", "complexType");
                        if (complexTypes.getLength() > 0) {
                             extractElementsFromComplexType((Element) complexTypes.item(0), params);
                        } else {
                            // Maybe it has a type attribute pointing to a complex type?
                            // For now just return the element name if no complex structure found
                            // Or maybe we should resolve the 'type' attribute... 
                            // Let's keep it simple: if no inline complex type, assume leaf or we'd need recursion.
                        }
                        return params;
                    }
                }
            }
        }
        return params;
    }

    private static void extractElementsFromComplexType(Element complexType, List<String> params) {
        NodeList elements = complexType.getElementsByTagNameNS("*", "element");
        for (int j = 0; j < elements.getLength(); j++) {
            Element elem = (Element) elements.item(j);
            String elemName = elem.getAttribute("name");
            if (elemName != null && !elemName.isEmpty()) {
                params.add(elemName);
            }
        }
    }

    public static String generateSoapRequest(Operation operation, String targetNamespace, Map<String, String> parameterValues) {
        StringBuilder soap = new StringBuilder();
        soap.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        soap.append("<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:web=\"" + targetNamespace + "\">\n");
        soap.append("   <soapenv:Header/>\n");
        soap.append("   <soapenv:Body>\n");
        soap.append("      <web:" + operation.getName() + ">\n");

        Input input = operation.getInput();
        if (input != null && input.getMessage() != null) {
            Map parts = input.getMessage().getParts();
            for (Object key : parts.keySet()) {
                Part part = (Part) parts.get(key);
                String paramName = part.getName();
                String typeName = part.getTypeName() != null ? part.getTypeName().getLocalPart() : "string";
                
                String value;
                if (parameterValues.containsKey(paramName)) {
                    value = parameterValues.get(paramName);
                } else {
                    value = getSmartValue(typeName);
                }
                
                soap.append("         <!--Optional-->\n");
                soap.append("         <web:" + paramName + ">" + value + "</web:" + paramName + ">\n");
            }
        }

        soap.append("      </web:" + operation.getName() + ">\n");
        soap.append("   </soapenv:Body>\n");
        soap.append("</soapenv:Envelope>");
        return soap.toString();
    }

    public static String generateSoapRequest(Operation operation, String targetNamespace, AttackType attackType) {
        StringBuilder soap = new StringBuilder();
        
        if (attackType == AttackType.XXE) {
            soap.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
            soap.append("<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\" > ]>\n");
        } else {
            soap.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        }
        
        soap.append("<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:web=\"" + targetNamespace + "\">\n");
        soap.append("   <soapenv:Header/>\n");
        soap.append("   <soapenv:Body>\n");
        soap.append("      <web:" + operation.getName() + ">\n");

        Input input = operation.getInput();
        if (input != null && input.getMessage() != null) {
            Map parts = input.getMessage().getParts();
            for (Object key : parts.keySet()) {
                Part part = (Part) parts.get(key);
                String typeName = part.getTypeName() != null ? part.getTypeName().getLocalPart() : "string";
                String value = getAttackValue(typeName, attackType);
                soap.append("         <!--Optional-->\n");
                soap.append("         <web:" + part.getName() + ">" + value + "</web:" + part.getName() + ">\n");
            }
        }

        soap.append("      </web:" + operation.getName() + ">\n");
        soap.append("   </soapenv:Body>\n");
        soap.append("</soapenv:Envelope>");
        return soap.toString();
    }
    public static String getEndpointUrl(Port port) {
        for (Object ext : port.getExtensibilityElements()) {
            if (ext instanceof javax.wsdl.extensions.soap.SOAPAddress) {
                return ((javax.wsdl.extensions.soap.SOAPAddress) ext).getLocationURI();
            } else if (ext instanceof javax.wsdl.extensions.soap12.SOAP12Address) {
                return ((javax.wsdl.extensions.soap12.SOAP12Address) ext).getLocationURI();
            } else if (ext instanceof javax.wsdl.extensions.http.HTTPAddress) {
                return ((javax.wsdl.extensions.http.HTTPAddress) ext).getLocationURI();
            } else {
                // Log unknown element for debugging
                System.out.println("Unknown extensibility element: " + ext.getClass().getName());
            }
        }
        return null;
    }

    private static String getAttackValue(String typeName, AttackType attackType) {
        if (attackType == AttackType.NORMAL) {
            return getSmartValue(typeName);
        }

        switch (attackType) {
            case SQLI:
                return "' OR '1'='1";
            case XSS:
                return "\"><script>alert(1)</script>";
            case XXE:
                return "&xxe;";
            case OVERFLOW:
                return "A".repeat(10000);
            default:
                return getSmartValue(typeName);
        }
    }

    private static String getSmartValue(String typeName) {
        String lowerType = typeName.toLowerCase();
        if (lowerType.contains("int") || lowerType.contains("long") || lowerType.contains("short")) {
            return "1337";
        } else if (lowerType.contains("string")) {
            return "test_string";
        } else if (lowerType.contains("bool")) {
            return "true";
        } else if (lowerType.contains("float") || lowerType.contains("double")) {
            return "123.45";
        } else if (lowerType.contains("date")) {
            return "2023-01-01";
        }
        return "?";
    }

    public static String getDocumentation(Operation operation) {
        Element docParams = operation.getDocumentationElement();
        if (docParams != null) {
            return docParams.getTextContent().trim();
        }
        return "No documentation available.";
    }
}
