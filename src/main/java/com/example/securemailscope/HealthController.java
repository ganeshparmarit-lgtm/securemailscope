package com.example.securemailscope;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HealthController {

    private final DnsLookupService dnsLookupService;

    public HealthController(DnsLookupService dnsLookupService) {
        this.dnsLookupService = dnsLookupService;
    }

    @GetMapping("/health")
    public String checkHealth() {
        return "SecureMailScope is running!";
    }

    @GetMapping("/spf")
    public String checkSpf(@RequestParam String domain) {
        return dnsLookupService.getSpfRecord(domain);
    }
}
