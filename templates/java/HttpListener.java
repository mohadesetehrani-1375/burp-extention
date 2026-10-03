package com.yourname.burp;

import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;

import java.util.List;

/**
 * HTTP Traffic Listener
 * 
 * This class implements IHttpListener to intercept and process
 * HTTP requests and responses passing through Burp Suite.
 */
public class HttpListener implements IHttpListener {
    
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    
    public HttpListener(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        this.callbacks = callbacks;
        this.helpers = helpers;
    }
    
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, 
                                   IHttpRequestResponse messageInfo) {
        try {
            if (messageIsRequest) {
                processRequest(toolFlag, messageInfo);
            } else {
                processResponse(toolFlag, messageInfo);
            }
        } catch (Exception e) {
            callbacks.printError("Error in HttpListener: " + e.getMessage());
        }
    }
    
    /**
     * Process HTTP requests
     */
    private void processRequest(int toolFlag, IHttpRequestResponse messageInfo) {
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
        String url = requestInfo.getUrl().toString();
        String method = requestInfo.getMethod();
        
        // Log request details
        callbacks.printOutput(String.format("[%s] %s %s", getToolName(toolFlag), method, url));
        
        // Example: Modify requests to specific domains
        // if (url.contains("example.com")) {
        //     modifyRequest(messageInfo);
        // }
    }
    
    /**
     * Process HTTP responses
     */
    private void processResponse(int toolFlag, IHttpRequestResponse messageInfo) {
        IResponseInfo responseInfo = helpers.analyzeResponse(messageInfo.getResponse());
        int statusCode = responseInfo.getStatusCode();
        
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
        String url = requestInfo.getUrl().toString();
        
        // Log response details
        callbacks.printOutput(String.format("[%s] Response %d from %s", 
            getToolName(toolFlag), statusCode, url));
        
        // Example: Check for specific response patterns
        // if (statusCode == 200) {
        //     checkResponseContent(messageInfo);
        // }
    }
    
    /**
     * Get tool name from flag
     */
    private String getToolName(int toolFlag) {
        switch (toolFlag) {
            case IBurpExtenderCallbacks.TOOL_PROXY:
                return "PROXY";
            case IBurpExtenderCallbacks.TOOL_SCANNER:
                return "SCANNER";
            case IBurpExtenderCallbacks.TOOL_INTRUDER:
                return "INTRUDER";
            case IBurpExtenderCallbacks.TOOL_REPEATER:
                return "REPEATER";
            default:
                return "OTHER";
        }
    }
}
