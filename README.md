# WSDL Raider

WSDL Raider is a Burp Suite extension designed to streamline the security testing of SOAP web services. It parses WSDL files, visualizes the service structure, generates smart SOAP requests, and includes a built-in fuzzer for discovering vulnerabilities like SQL Injection, XSS, and XXE.

## Features

### WSDL Parsing & Visualization
- **Context Menu Integration:** Right-click on any request/response to "Parse WSDL".
- **Tree View:** Visualizes Services, Ports, and Operations in a clean tree structure.
- **Documentation:** Displays WSDL documentation for selected operations.

### Advanced Request Generation
- **Dynamic Form:** Automatically generates a form for editing operation parameters.
- **Smart Defaults:** Pre-fills parameters with type-aware values (e.g., integers, dates).
- **Quick Execute:** Send requests immediately and view the response within the extension.
- **Repeater Integration:** One-click "Send to Repeater" for manual testing.
- **Redirect Support:** Option to automatically follow HTTP redirects (3xx).

### WSDL Fuzzer
- **Targeted Fuzzing:** Scope fuzzing to specific parameters or all parameters.
- **Attack Modes:** Built-in payloads for SQL Injection, XSS, XXE, Overflow, and Format Strings.
- **Custom Payloads:** Load payloads from files or paste from clipboard.
- **Real-time Results:** View status codes, response lengths, and full request/response details for each attempt.
- **Concurrency:** Multi-threaded execution for fast scanning.

## Installation

1. Download the latest `WsdlRaider.jar` from the releases page.
2. Open Burp Suite.
3. Go to **Extensions** -> **Installed**.
4. Click **Add**.
5. Select **Java** as the extension type.
6. Select the `WsdlRaider.jar` file.

## Usage

1. **Load WSDL:**
   - Right-click a request/response containing WSDL content and select **Extensions** -> **WSDL Raider** -> **Parse WSDL**.
   - Or, go to the **WSDL Raider** tab and click **Load WSDL File** to load from disk.

2. **Test Operations:**
   - Select an operation from the tree on the left.
   - Edit parameter values in the form on the right.
   - Click **Quick Execute** to test immediately or **Send to Repeater** for further manual testing.

3. **Fuzzing:**
   - Switch to the **WSDL Fuzzer** tab.
   - Select the **Target Parameter** (or "All Parameters").
   - Choose an **Attack Type** or enter custom payloads.
   - Click **Start Fuzzing**.
   - Click on any result row to view the full request and response.

## Building from Source

Requirements:
- JDK 17+
- Gradle

```bash
git clone https://github.com/yourusername/wsdl-raider.git
cd wsdl-raider
./gradlew build
```

The compiled JAR will be in `build/libs/`.

## License

This project is licensed under the MIT License.
