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
}