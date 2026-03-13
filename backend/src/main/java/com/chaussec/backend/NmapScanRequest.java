package com.chaussec.backend;

import java.util.ArrayList;
import java.util.List;

public record NmapScanRequest(String scanType, String target, List<String> targets) {

    public List<String> getTargets() {
        List<String> mergedTargets = new ArrayList<>();

        if (target != null && !target.isBlank()) {
            mergedTargets.add(target);
        }

        if (targets != null) {
            for (String value : targets) {
                if (value != null && !value.isBlank()) {
                    mergedTargets.add(value);
                }
            }
        }

        return mergedTargets;
    }
}
