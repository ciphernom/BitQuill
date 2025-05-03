use crate::merkle::types::*;
use std::time::{Instant, SystemTime, Duration};

impl MerkleDocument {
    // Analyze writing patterns
    pub fn analyze_writing_patterns(&self) -> WritingPatternResult {
        let intervals: Vec<u64> = self.edit_intervals.iter()
            .filter(|(_, interval)| *interval > 0) // Skip first entry with 0 interval
            .map(|(_, interval)| *interval)
            .collect();
        
        if intervals.len() < 5 {
            // Not enough data for meaningful analysis
            return WritingPatternResult {
                average_interval: 0,
                interval_deviation: 0.0,
                detected_anomalies: Vec::new(),
            };
        }
        
        // Calculate basic statistics
        let avg_interval = if intervals.is_empty() {
            0
        } else {
            intervals.iter().sum::<u64>() / intervals.len() as u64
        };
        
        // Calculate standard deviation
        let variance: f64 = if intervals.is_empty() || avg_interval == 0 {
            0.0
        } else {
            intervals.iter()
                .map(|&i| {
                    let diff = i as f64 - avg_interval as f64;
                    diff * diff
                })
                .sum::<f64>() / intervals.len() as f64
        };
        
        let std_dev = variance.sqrt();
        
        // Detect anomalies - intervals that are significant outliers
        let mut anomalies = Vec::new();
        
        // Map intervals to leaf numbers (excluding first which has no interval)
        let mut intervals_with_leaf: Vec<(u64, u64)> = Vec::new();
        let mut current_leaf = 1;
        
        for interval in &intervals {
            // i+1 because we skip the first entry in edit_intervals (which has 0 interval)
            intervals_with_leaf.push((*interval, current_leaf));
            current_leaf += 1;
        }
        
        // Find outliers (more than 3 standard deviations from mean)
        if std_dev > 0.0 {  // Prevent division by zero
            for (interval, leaf_number) in intervals_with_leaf {
                let z_score = (interval as f64 - avg_interval as f64) / std_dev;
                
                if z_score.abs() > 3.0 {
                    let description = if z_score > 0.0 {
                        format!("Unusually long pause ({} seconds vs avg {}) - possible session break", 
                                interval, avg_interval)
                    } else {
                        format!("Unusually rapid edit ({} seconds vs avg {}) - possible bulk insertion", 
                                interval, avg_interval)
                    };
                    
                    anomalies.push(WritingPatternAnomaly {
                        leaf_number,
                        description,
                        confidence: (z_score.abs() - 3.0) / 2.0, // Scale confidence (0.0-1.0)
                    });
                }
            }
        }
        
        // Look for sustained bursts of activity
        if intervals.len() >= 10 {
            let windows = intervals.windows(10);
            let mut window_idx = 0;
            
            for window in windows {
                if window.is_empty() {
                    continue;
                }
                
                let window_avg = window.iter().sum::<u64>() / window.len() as u64;
                
                // If a sustained period is significantly faster than overall average
                if window_avg < avg_interval / 3 && window_avg > 0 {
                    let leaf_start = window_idx + 1; // +1 because we skip first entry with 0 interval
                    let leaf_end = leaf_start + window.len() as u64;
                    
                    anomalies.push(WritingPatternAnomaly {
                        leaf_number: leaf_start, // Reference starting leaf of the burst
                        description: format!("Sustained rapid editing detected over leaves #{}-#{} (avg interval: {} vs global: {})",
                                            leaf_start, leaf_end, window_avg, avg_interval),
                        confidence: 0.7, // High confidence for sustained patterns
                    });
                }
                
                window_idx += 1;
            }
        }
        
        WritingPatternResult {
            average_interval: avg_interval,
            interval_deviation: std_dev,
            detected_anomalies: anomalies,
        }
    }
}
