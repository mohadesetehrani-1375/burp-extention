#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Burp Suite Extension - Python Template

This template provides a starting point for developing Burp Suite extensions
using Python (Jython).
"""

from burp import IBurpExtender
from burp import IHttpListener
from burp import IScannerCheck
from java.io import PrintWriter


class BurpExtender(IBurpExtender):
    """
    Main extension entry point.
    
    This class implements IBurpExtender, which is required for all
    Burp Suite extensions.
    """
    
    def registerExtenderCallbacks(self, callbacks):
        """
        Called when the extension is loaded.
        
        Args:
            callbacks: IBurpExtenderCallbacks object for interacting with Burp
        """
        # Store references for later use
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Set extension name
        callbacks.setExtensionName("My Python Extension")
        
        # Set up output streams
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        
        # Log successful load
        self._stdout.println("Extension loaded successfully!")
        self._stdout.println("Burp Version: " + callbacks.getBurpVersion()[1])
        
        # Register listeners
        callbacks.registerHttpListener(HttpListener(self))
        # callbacks.registerScannerCheck(ScannerCheck(self))
        
        return


class HttpListener(IHttpListener):
    """
    HTTP traffic listener.
    
    Intercepts and processes HTTP requests and responses.
    """
    
    def __init__(self, extender):
        """
        Initialize the HTTP listener.
        
        Args:
            extender: Reference to the main BurpExtender instance
        """
        self._extender = extender
        self._callbacks = extender._callbacks
        self._helpers = extender._helpers
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """
        Process HTTP messages.
        
        Args:
            toolFlag: Flag indicating which Burp tool generated the traffic
            messageIsRequest: True if this is a request, False for response
            messageInfo: IHttpRequestResponse object containing the message
        """
        try:
            if messageIsRequest:
                self.processRequest(toolFlag, messageInfo)
            else:
                self.processResponse(toolFlag, messageInfo)
        except Exception as e:
            self._extender._stderr.println("Error in HttpListener: " + str(e))
    
    def processRequest(self, toolFlag, messageInfo):
        """
        Process HTTP requests.
        
        Args:
            toolFlag: Tool that generated the request
            messageInfo: Request information
        """
        requestInfo = self._helpers.analyzeRequest(messageInfo)
        url = str(requestInfo.getUrl())
        method = requestInfo.getMethod()
        
        # Log request details
        tool_name = self.getToolName(toolFlag)
        self._extender._stdout.println(
            "[{0}] {1} {2}".format(tool_name, method, url)
        )
    
    def processResponse(self, toolFlag, messageInfo):
        """
        Process HTTP responses.
        
        Args:
            toolFlag: Tool that generated the request
            messageInfo: Response information
        """
        responseInfo = self._helpers.analyzeResponse(messageInfo.getResponse())
        statusCode = responseInfo.getStatusCode()
        
        requestInfo = self._helpers.analyzeRequest(messageInfo)
        url = str(requestInfo.getUrl())
        
        # Log response details
        tool_name = self.getToolName(toolFlag)
        self._extender._stdout.println(
            "[{0}] Response {1} from {2}".format(tool_name, statusCode, url)
        )
    
    def getToolName(self, toolFlag):
        """
        Get tool name from flag.
        
        Args:
            toolFlag: Tool flag constant
            
        Returns:
            Human-readable tool name
        """
        from burp import IBurpExtenderCallbacks
        
        tool_names = {
            IBurpExtenderCallbacks.TOOL_PROXY: "PROXY",
            IBurpExtenderCallbacks.TOOL_SCANNER: "SCANNER",
            IBurpExtenderCallbacks.TOOL_INTRUDER: "INTRUDER",
            IBurpExtenderCallbacks.TOOL_REPEATER: "REPEATER",
        }
        return tool_names.get(toolFlag, "OTHER")


class ScannerCheck(IScannerCheck):
    """
    Custom scanner check.
    
    Implements custom vulnerability detection logic.
    """
    
    def __init__(self, extender):
        """
        Initialize the scanner check.
        
        Args:
            extender: Reference to the main BurpExtender instance
        """
        self._extender = extender
        self._callbacks = extender._callbacks
        self._helpers = extender._helpers
    
    def doPassiveScan(self, baseRequestResponse):
        """
        Perform passive scan on a request/response.
        
        Args:
            baseRequestResponse: The request/response to scan
            
        Returns:
            List of IScanIssue objects, or None if no issues found
        """
        # TODO: Implement passive scan logic
        return None
    
    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """
        Perform active scan using an insertion point.
        
        Args:
            baseRequestResponse: The base request/response
            insertionPoint: The insertion point to use
            
        Returns:
            List of IScanIssue objects, or None if no issues found
        """
        # TODO: Implement active scan logic
        return None
    
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        """
        Determine if two issues are duplicates.
        
        Args:
            existingIssue: The existing issue
            newIssue: The new issue to compare
            
        Returns:
            0 to keep both issues, 1 to keep existing, -1 to keep new
        """
        return 0
