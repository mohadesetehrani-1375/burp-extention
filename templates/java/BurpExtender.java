package com.yourname.burp;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;

/**
 * Burp Suite Extension Entry Point
 * 
 * This class implements the IBurpExtender interface, which is required
 * for all Burp Suite extensions.
 */
public class BurpExtender implements IBurpExtender {
    
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // Store references for later use
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        
        // Set extension name
        callbacks.setExtensionName("My Burp Extension");
        
        // Log successful load
        callbacks.printOutput("Extension loaded successfully!");
        callbacks.printOutput("Burp Version: " + callbacks.getBurpVersion()[1]);
        
        // Register listeners here
        // callbacks.registerHttpListener(new HttpListener(callbacks, helpers));
        // callbacks.registerScannerCheck(new ScannerCheck(callbacks, helpers));
    }
    
    /**
     * Get the callbacks object
     */
    public IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }
    
    /**
     * Get the helpers object
     */
    public IExtensionHelpers getHelpers() {
        return helpers;
    }
}
