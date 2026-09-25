package com.example.securemailscope;

import org.springframework.stereotype.Service;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;

@Service
public class DnsLookupService {

    public String getSpfRecord(String domain) {
        try {
            Lookup lookup = new Lookup(domain, Type.TXT);
            Record[] records = lookup.run();

            if (records == null) {
                return "No TXT records found for this domain";
            }

            for (Record record : records) {
                TXTRecord txt = (TXTRecord) record;

                // Join all the split string segments into one clean string
                StringBuilder fullValue = new StringBuilder();
                for (Object segment : txt.getStrings()) {
                    fullValue.append(segment.toString());
                }

                String value = fullValue.toString();

                if (value.contains("v=spf1")) {
                    return value;
                }
            }

            return "No SPF record found";

        } catch (Exception e) {
            return "Error looking up domain: " + e.getMessage();
        }
    }

        public String getDmarcRecord(String domain){
            String dmarcDomain = "_dmarc." + domain;

            try {
                Lookup lookup = new Lookup(dmarcDomain,Type.TXT);
                Record[] records = lookup.run();

                if(records == null){
                    return "No TXT records found for this domain";
                }
                for(Record record : records){
                    TXTRecord txt = (TXTRecord) record;

                    // Join all the split string segments into one clean string
                    StringBuilder fullValue = new StringBuilder();
                    for (Object segment : txt.getStrings()) {
                        fullValue.append(segment.toString());
                    }
                    String value = fullValue.toString();

                    if (value.contains("v=DMARC1")) {
                        return value;
                    }
                }

                return "No DMARC record found";

            } catch (Exception e) {
                return "Error looking up domain: " + e.getMessage();
            }
        }

    public String getDkimRecord(String domain) {
        String[] commonSelectors = {"google", "selector1", "selector2", "default", "k1"};

        for (String selector : commonSelectors) {
            String dkimDomain = selector + "._domainkey." + domain;

            try {
                Lookup lookup = new Lookup(dkimDomain, Type.TXT);
                Record[] records = lookup.run();

                if (records != null) {
                    for (Record record : records) {
                        TXTRecord txt = (TXTRecord) record;

                        StringBuilder fullValue = new StringBuilder();
                        for (Object segment : txt.getStrings()) {
                            fullValue.append(segment.toString());
                        }

                        String value = fullValue.toString();

                        if (value.contains("v=DKIM1") || value.contains("k=rsa")) {
                            return "DKIM found using selector '" + selector + "': " + value;
                        }
                    }
                }

            } catch (Exception e) {
                // is selector ke saath nahi mila, agla try karo
            }
        }

        return "DKIM not detected using known selectors (google, selector1, selector2, default, k1)";
    }
}


