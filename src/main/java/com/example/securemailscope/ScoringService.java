package com.example.securemailscope;

import org.springframework.stereotype.Service;


@Service
public class ScoringService {

    private final DnsLookupService dnsLookupService;

    public ScoringService(DnsLookupService dnsLookupService){
        this.dnsLookupService = dnsLookupService;
    }

    public int CalculateScore(String domain){
        int score = 100;

        String spfResult = dnsLookupService.getSpfRecord(domain);
        if(spfResult.contains("No SPF record found") || spfResult.contains("Error")){
            score = score - 30;
        }

        String dmarcResult = dnsLookupService.getDmarcRecord(domain);
        if(dmarcResult.contains("No DMARC record found") || dmarcResult.contains("Error")){
            score = score - 30;
        } else if (dmarcResult.contains("p=none")) {
            score = score - 15;
        } else if (dmarcResult.contains("p=reject")) {
            score = score + 10;
        }

        String dkimResult = dnsLookupService.getDkimRecord(domain);
        if(dkimResult.contains("not detected") || dkimResult.contains("REVOKED") || dkimResult.contains("Error")){
            score = score - 20;
        }

        return score;
    }

}
