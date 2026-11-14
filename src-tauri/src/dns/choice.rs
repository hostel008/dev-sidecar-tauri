//! 动态优选：成功/失败计数、连续失败切换备选（对应原版 lib/choice）

use serde_json::json;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Counter {
    pub value: String,
    pub total: f64,
    pub error: f64,
    pub keep_error_count: u32,
    pub success_rate: f64,
}

impl Counter {
    pub fn new(value: &str, total: f64, success_rate: f64) -> Self {
        Counter {
            value: value.to_string(),
            total,
            error: 0.0,
            keep_error_count: 0,
            success_rate,
        }
    }
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "value": self.value,
            "total": self.total,
            "error": self.error,
            "keepErrorCount": self.keep_error_count,
            "successRate": self.success_rate,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DynamicChoice {
    pub key: String,
    pub count_map: HashMap<String, Counter>,
    pub value: Option<String>,
    pub backup_list: Vec<String>,
}

impl DynamicChoice {
    pub fn new(key: &str) -> Self {
        DynamicChoice {
            key: key.to_string(),
            count_map: HashMap::new(),
            value: None,
            backup_list: Vec::new(),
        }
    }

    /// 依据成功率重排 backupList
    pub fn do_rank(&mut self) {
        let mut list: Vec<Counter> = self.count_map.values().cloned().collect();
        list.sort_by(|a, b| {
            b.success_rate
                .partial_cmp(&a.success_rate)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let new_list: Vec<String> = list.iter().map(|c| c.value.clone()).collect();
        self.set_backup_list(new_list);
    }

    pub fn set_backup_list(&mut self, new_backup_list: Vec<String>) {
        self.backup_list = new_backup_list.clone();
        let mut default_total = new_backup_list.len() as f64;
        for ip in &new_backup_list {
            if !self.count_map.contains_key(ip) {
                self.count_map
                    .insert(ip.clone(), Counter::new(ip, default_total, 0.5));
                default_total -= 1.0;
            }
        }
        if !self.backup_list.is_empty() {
            let first = self.backup_list.remove(0);
            self.value = Some(first.clone());
            self.do_count(&first, false);
        } else {
            self.value = None;
        }
    }

    fn change_next(&mut self, ip: &str) {
        if let Some(count) = self.count_map.get_mut(ip) {
            count.keep_error_count = 0;
            count.total = 0.0;
            count.error = 0.0;
        }
        let previous = self.value.clone();
        if !self.backup_list.is_empty() {
            let next = self.backup_list.remove(0);
            log_info!("切换备选 {} : {:?} ➜ {}", self.key, previous, next);
            self.value = Some(next);
        } else {
            log_info!(
                "切换备选 {} : {:?} ➜ None (backupList 已空)",
                self.key,
                previous
            );
            self.value = None;
        }
    }

    pub fn do_count(&mut self, ip: &str, is_error: bool) {
        let entry = self
            .count_map
            .entry(ip.to_string())
            .or_insert_with(|| Counter::new(ip, 5.0, 1.0));

        if is_error {
            entry.error += 1.0;
            entry.keep_error_count += 1;
        } else {
            entry.keep_error_count = 0;
        }
        entry.total += 1.0;
        entry.success_rate = 1.0 - (entry.error / entry.total);

        let keep = entry.keep_error_count;
        let rate = entry.success_rate;
        if is_error && self.value.as_deref() == Some(ip) {
            if keep >= 1 || rate < 0.4 {
                self.change_next(ip);
            }
        }
    }
}
