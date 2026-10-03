---
name: burpsuite-extension-skill
description: Develop Burp Suite extensions in Java (Montoya API) or Python (Jython). Supports creating HTTP listeners, scanner checks, intruder payloads, UI tabs, and context menus. Includes project templates, multi-platform setup guides, and best practices.
version: 1.0.0
license: MIT
tags:
  - burp
  - security
  - extension
  - java
  - python
  - jython
  - penetration-testing
  - web-security
allowed-tools: Bash Read Write Edit
---

# Burp Suite Extension Development Skill

Develop Burp Suite extensions in **Java** (Montoya API) or **Python** (Jython).

## Quick Start

### When to Use This Skill

Use this skill when you need to:
- Create a new Burp Suite extension from scratch
- Implement HTTP traffic interception or modification
- Build custom vulnerability scanner checks
- Generate custom intruder payloads
- Add UI tabs or context menus to Burp Suite

### What This Skill Provides

- **Project Templates**: Ready-to-use Java and Python templates
- **Multi-Platform Setup**: macOS, Windows, and Linux guides
- **Best Practices**: Error handling, performance, and security
- **Official Resources**: Links to PortSwigger documentation

---

## Choose Your Language

| Feature | Java (Montoya API) | Python (Jython) |
|---------|-------------------|-----------------|
| API Version | Montoya API (New) | Extender API (Legacy) |
| Java Version | JDK 21+ | JDK 17+ |
| Performance | Best | Slower |
| Setup Complexity | Medium | Simple |
| Best For | Production extensions | Quick scripts/prototypes |

**Recommendation**: Use Java for production extensions. Use Python for rapid prototyping.

---

## Environment Setup

### macOS

```bash
# Install Java 21
brew install openjdk@21
echo 'export PATH="/opt/homebrew/opt/openjdk@21/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc

# Verify installation
java -version

# Install IntelliJ IDEA (optional)
brew install --cask intellij-idea-ce
```

### Windows

```powershell
# Install Java 21
winget install EclipseAdoptium.Temurin.21.JDK

# Set environment variables
$env:JAVA_HOME = "C:\Program Files\Eclipse Adoptium\jdk-21"
$env:Path += ";$env:JAVA_HOME\bin"

# Verify installation
java -version
```

### Linux (Ubuntu/Debian)

```bash
# Install Java 21
sudo apt-get update
sudo apt-get install temurin-21-jdk

# Verify installation
java -version

# Install IntelliJ IDEA (optional)
sudo snap install intellij-idea-community --classic
```

---

## Path A: Java Development (Recommended)

### Prerequisites

1. **Burp Suite** - [Download Community Edition](https://portswigger.net/burp/communitydownload)
2. **Java JDK 21+** - [Download from Adoptium](https://adoptium.net/)
3. **IntelliJ IDEA** (Optional) - [Download](https://www.jetbrains.com/idea/)

### Quick Start with Starter Project

```bash
# Clone the official starter project
git clone https://github.com/PortSwigger/burp-extensions-montoya-api-starter.git my-extension
cd my-extension

# Build
./gradlew build  # macOS/Linux
gradlew.bat build  # Windows

# Output: build/libs/my-extension.jar
```

### Load Extension in Burp Suite

1. Open Burp Suite
2. Go to **Extensions** → **Installed**
3. Click **Add**
4. Select **Java** as extension type
5. Browse to `build/libs/my-extension.jar`
6. Click **Next**

### Key Interfaces

#### Extension Entry Point

```java
package burp.extension;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class MyExtension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("My Extension");
        api.logging().logToOutput("Extension loaded successfully!");
    }
}
```

#### HTTP Proxy Handler

```java
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;

public class MyProxyHandler implements ProxyRequestHandler {
    private final MontoyaApi api;
    
    public MyProxyHandler(MontoyaApi api) {
        this.api = api;
    }
    
    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        api.logging().logToOutput("Request: " + interceptedRequest.url());
        return ProxyRequestReceivedAction.continueWith(interceptedRequest);
    }
    
    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
    }
}
```

#### Scanner Check

```java
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.http.message.HttpRequestResponse;

public class MyScanCheck implements ScanCheck {
    private final MontoyaApi api;
    
    public MyScanCheck(MontoyaApi api) {
        this.api = api;
    }
    
    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        // Implement passive scan logic
        return null;
    }
    
    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, 
                                    AuditResult auditResult) {
        // Implement active scan logic
        return null;
    }
}
```

### Registering Components

```java
public class MyExtension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("My Extension");
        
        // Register components
        api.proxy().registerRequestHandler(new MyProxyHandler(api));
        api.scanner().registerScanCheck(new MyScanCheck(api));
        api.userInterface().registerSuiteTab("My Extension", new MyTab());
    }
}
```

### Project Structure

```
my-extension/
├── src/main/java/
│   └── burp/extension/
│       ├── MyExtension.java
│       ├── MyProxyHandler.java
│       └── MyScanCheck.java
├── build.gradle
├── settings.gradle
└── README.md
```

### build.gradle

```groovy
plugins {
    id 'java'
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

repositories {
    mavenCentral()
}

dependencies {
    implementation 'net.portswigger.burp.extensions:montoya-api:2.3.+'
}

tasks.named('jar') {
    manifest {
        attributes 'Extension-ClassName': 'burp.extension.MyExtension'
    }
}
```

---

## Path B: Python Development (Jython)

### Prerequisites

1. **Burp Suite** - [Download Community Edition](https://portswigger.net/burp/communitydownload)
2. **Jython** - [Download Standalone JAR](https://www.jython.org/download)

### Setup Jython in Burp Suite

1. Open Burp Suite
2. Go to **Settings** → **Extensions** → **Python Environment**
3. Set path to Jython JAR file

### Python Extension Template

```python
# burp_extender.py
from burp import IBurpExtender
from burp import IHttpListener
from java.io import PrintWriter

class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("My Python Extension")
        
        # Setup output streams
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        
        self._stdout.println("Extension loaded!")
        
        # Register listeners
        callbacks.registerHttpListener(HttpListener(self))

class HttpListener(IHttpListener):
    def __init__(self, extender):
        self._extender = extender
        self._callbacks = extender._callbacks
        self._helpers = extender._helpers
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            if messageIsRequest:
                requestInfo = self._helpers.analyzeRequest(messageInfo)
                url = str(requestInfo.getUrl())
                self._extender._stdout.println("Request: " + url)
        except Exception as e:
            self._extender._stderr.println("Error: " + str(e))
```

### Load Python Extension

1. Open Burp Suite
2. Go to **Extensions** → **Installed** → **Add**
3. Select **Python** as extension type
4. Browse to `burp_extender.py`
5. Click **Next**

---

## Best Practices

### 1. Error Handling

Always wrap your code in try-catch blocks to prevent extension crashes:

**Java:**
```java
@Override
public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
    try {
        // Your logic here
        return ProxyRequestReceivedAction.continueWith(interceptedRequest);
    } catch (Exception e) {
        api.logging().logToError("Error: " + e.getMessage());
        return ProxyRequestReceivedAction.continueWith(interceptedRequest);
    }
}
```

**Python:**
```python
def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
    try:
        # Your logic here
    except Exception as e:
        self._extender._stderr.println("Error: " + str(e))
```

### 2. Performance

- **Never block** in HTTP listeners - use async processing
- **Cache results** for repeated operations
- **Limit scope** - check `isInScope()` before heavy processing

### 3. Logging

Use Burp's logging API instead of System.out:

**Java:**
```java
api.logging().logToOutput("Info message");
api.logging().logToError("Error message");
```

**Python:**
```python
self._stdout.println("Info message")
self._stderr.println("Error message")
```

### 4. Scope Checking

Only process in-scope requests to improve performance:

**Java:**
```java
if (api.scope().isInScope(request.url())) {
    // Process request
}
```

**Python:**
```python
if self._callbacks.isInScope(requestInfo.getUrl()):
    # Process request
```

### 5. Resource Cleanup

Register unload handlers to clean up resources:

```java
api.extension().registerUnloadHandler(() -> {
    api.logging().logToOutput("Extension unloading...");
    // Cleanup resources
});
```

---

## Debugging

### Java (IntelliJ)

1. Add JVM argument to Burp Suite:
   ```
   -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005
   ```
2. In IntelliJ: Run → Edit Configurations → Remote JVM Debug
3. Set port to 5005
4. Start Burp Suite with JVM argument
5. Attach debugger in IntelliJ

### Python

- Use `self._stdout.println()` for logging
- Check **Extensions** → **Output** tab in Burp Suite

---

## Common Issues

| Issue | Solution |
|-------|----------|
| Extension won't load | Check Java version (21+ required for Montoya API) |
| ClassNotFoundException | Verify Montoya API dependency in build.gradle |
| Python import errors | Check Jython version and path configuration |
| No HTTP traffic | Ensure listener is registered in initialize() |
| Performance issues | Use async processing, limit scope with isInScope() |
| OutOfMemoryError | Increase JVM heap size: `-Xmx1g` |

---

## Limitations

- **Java Extensions**: Require JDK 21+ for Montoya API
- **Python Extensions**: Use Jython (Python 2.7 compatible), not Python 3
- **Network**: Some features require Burp Suite Professional
- **Platform**: Extensions run inside Burp Suite JVM

---

## Official Resources

### Documentation
- [Creating Extensions](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating)
- [Starter Project](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/set-up/starter-project)
- [First Extension Guide](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/first-extension)

### API References
- [Montoya API JavaDoc](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/)
- [Montoya API GitHub](https://github.com/PortSwigger/burp-extensions-montoya-api)
- [Example Extensions](https://github.com/PortSwigger/burp-extensions-montoya-api-examples)
- [Legacy Extender API](https://portswigger.net/burp/extender/api/)

### Community
- [BApp Store](https://portswigger.net/bappstore)
- [Burp Suite Documentation](https://portswigger.net/burp/documentation)

---

## Examples

### Example 1: Simple Request Logger

Log all HTTP requests passing through Burp Proxy:

```java
public class RequestLogger implements ProxyRequestHandler {
    private final MontoyaApi api;
    
    public RequestLogger(MontoyaApi api) {
        this.api = api;
    }
    
    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        api.logging().logToOutput("[" + interceptedRequest.httpService().host() + "] " + 
                                   interceptedRequest.method() + " " + interceptedRequest.url());
        return ProxyRequestReceivedAction.continueWith(interceptedRequest);
    }
    
    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
    }
}
```

### Example 2: Custom Header Check

Detect missing security headers:

```java
public class SecurityHeaderCheck implements ScanCheck {
    private final MontoyaApi api;
    
    public SecurityHeaderCheck(MontoyaApi api) {
        this.api = api;
    }
    
    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        HttpResponse response = baseRequestResponse.response();
        
        if (response != null) {
            List<String> headers = response.headers();
            boolean hasXFrameOptions = headers.stream()
                .anyMatch(h -> h.toLowerCase().contains("x-frame-options"));
            
            if (!hasXFrameOptions) {
                // Report issue
            }
        }
        
        return null;
    }
    
    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, 
                                    AuditResult auditResult) {
        return null;
    }
}
```

---

## FAQ

**Q: Which language should I choose?**
A: Use Java for production extensions (better performance, newer API). Use Python for quick scripts and prototyping.

**Q: Can I use Python 3?**
A: No, Burp Suite uses Jython which supports Python 2.7 syntax only.

**Q: Do I need Burp Suite Professional?**
A: Community Edition works for most extensions. Some features (like scanner) require Professional.

**Q: How do I debug my extension?**
A: Use IntelliJ remote debugging for Java. Use print statements and Burp's Output tab for Python.
