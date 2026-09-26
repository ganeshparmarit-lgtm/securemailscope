package com.example.securemailscope;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HealthController {

    private final DnsLookupService dnsLookupService;
    private final ScoringService scoringService;

    public HealthController(DnsLookupService dnsLookupService, ScoringService scoringService) {
        this.dnsLookupService = dnsLookupService;
        this.scoringService = scoringService;
    }

    @GetMapping("/health")
    public String checkHealth() {
        return "SecureMailScope is running!";
    }

    @GetMapping("/spf")
    public String checkSpf(@RequestParam String domain) {
        return dnsLookupService.getSpfRecord(domain);
    }

    @GetMapping("/dmarc")
    public String checkDmarc(@RequestParam String domain) {
        return dnsLookupService.getDmarcRecord(domain);
    }

    @GetMapping("/dkim")
    public String checkDkim(@RequestParam String domain) {
        return dnsLookupService.getDkimRecord(domain);
    }

    @GetMapping("/score")
    public int checkScore(@RequestParam String domain){
        return scoringService.CalculateScore(domain);
    }
}
