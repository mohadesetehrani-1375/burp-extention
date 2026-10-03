# Burp Suite Extension Development Skill

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive skill for developing Burp Suite extensions in Java (Montoya API) or Python (Jython).

## Features

- **Dual Language Support**: Java (Montoya API) and Python (Jython)
- **Multi-Platform Setup**: macOS, Windows, and Linux environments
- **Project Generator**: Quick project scaffolding with templates
- **Best Practices**: Error handling, performance, and security guidelines
- **Official Resources**: Links to PortSwigger documentation and examples

## Quick Start

### Install the Skill

```bash
npx skills add gandli/burpsuite-extension-skill
```

### Create a New Project

```bash
# Java extension (recommended)
python scripts/main.py create my-extension --lang java

# Python extension
python scripts/main.py create my-extension --lang python

# List available templates
python scripts/main.py list-templates
```

## Language Comparison

| Feature | Java (Montoya API) | Python (Jython) |
|---------|-------------------|-----------------|
| API | Montoya API (New) | Extender API (Legacy) |
| Java Version | JDK 21+ | JDK 17+ |
| Performance | Best | Slower |
| Setup Complexity | Medium | Simple |
| Best For | Production extensions | Quick scripts/prototypes |

## Environment Setup

### macOS

```bash
# Install Java 21
brew install openjdk@21
echo 'export PATH="/opt/homebrew/opt/openjdk@21/bin:$PATH"' >> ~/.zshrc

# Install IntelliJ IDEA
brew install --cask intellij-idea-ce
```

### Windows

```powershell
# Install Java 21
winget install EclipseAdoptium.Temurin.21.JDK

# Set environment variables
$env:JAVA_HOME = "C:\Program Files\Eclipse Adoptium\jdk-21"
$env:Path += ";$env:JAVA_HOME\bin"
```

### Linux (Ubuntu/Debian)

```bash
# Install Java 21
sudo apt-get install temurin-21-jdk

# Install IntelliJ IDEA
sudo snap install intellij-idea-community --classic
```

## Project Structure

### Java (Gradle)

```text
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

### Python (Jython)

```text
my-extension/
├── burp_extender.py
├── requirements.txt
└── README.md
```

## Key Interfaces

### Java (Montoya API)

```java
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class MyExtension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("My Extension");
        api.logging().logToOutput("Extension loaded!");
    }
}
```

### Python (Jython)

```python
from burp import IBurpExtender
from java.io import PrintWriter

class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName("My Extension")
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stdout.println("Extension loaded!")
```

## Best Practices

1. **Error Handling**: Always use try-catch blocks in listeners
2. **Performance**: Never block in HTTP listeners, use async processing
3. **Logging**: Use Burp's logging API, not System.out
4. **Scope Checking**: Always check `isInScope()` before heavy processing
5. **Thread Safety**: Use thread-safe collections for shared data
6. **Resource Cleanup**: Register unload handlers for cleanup

## Official Resources

- [Creating Extensions](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating)
- [Montoya API JavaDoc](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/)
- [Montoya API GitHub](https://github.com/PortSwigger/burp-extensions-montoya-api)
- [Example Extensions](https://github.com/PortSwigger/burp-extensions-montoya-api-examples)
- [Legacy Extender API](https://portswigger.net/burp/extender/api/)
- [BApp Store](https://portswigger.net/bappstore)

## License

MIT License - see [LICENSE](LICENSE) for details.
