use anyhow::{ Result };
use std::collections::HashMap;
use std::{ fs };
use std::path::{ Path };
use tracing::{ debug, error, warn };

// Constants
const MAX_SECTIONS: usize = 100;
const MAX_ENTRIES_PER_SECTION: usize = 100;

// Types
pub type ConfigValue = String;
pub type ConfigSection = HashMap<String, ConfigValue>;

#[derive(Debug, Clone)]
pub struct Config {
    sections: HashMap<String, ConfigSection>,
}

impl Config {
    pub fn new() -> Self {
        Self {
            sections: HashMap::new(),
        }
    }

    pub fn set_value(&mut self, section: &str, key: &str, value: &str) -> Result<()> {
        if section.is_empty() || key.is_empty() {
            return Err(anyhow::anyhow!("Section or key cannot be empty"));
        }

        if self.sections.len() >= MAX_SECTIONS {
            return Err(anyhow::anyhow!("Maximum number of sections ({}) reached", MAX_SECTIONS));
        }

        let section_map = self.sections.entry(section.to_string()).or_insert_with(HashMap::new);

        if section_map.len() >= MAX_ENTRIES_PER_SECTION {
            return Err(
                anyhow::anyhow!(
                    "Maximum entries per section ({}) reached for section '{}'",
                    MAX_ENTRIES_PER_SECTION,
                    section
                )
            );
        }

        debug!("Setting config: [{}] {} = {}", section, key, value);
        section_map.insert(key.to_string(), value.to_string());
        Ok(())
    }

    pub fn get_value(&self, section: &str, key: &str) -> Option<&str> {
        self.sections
            .get(section)
            .and_then(|section_map| section_map.get(key))
            .map(|v| v.as_str())
    }

    // pub fn get_int(&self, section: &str, key: &str, default: i32) -> i32 {
    //     match self.get_value(section, key) {
    //         Some(val) =>
    //             match val.parse::<i32>() {
    //                 Ok(num) => num,
    //                 Err(_) => {
    //                     warn!(
    //                         "Invalid integer value '{}' for {}.{}, using default {}",
    //                         val,
    //                         section,
    //                         key,
    //                         default
    //                     );
    //                     default
    //                 }
    //             }
    //         None => {
    //             debug!("Using default value {} for {}.{}", default, section, key);
    //             default
    //         }
    //     }
    // }

    // pub fn get_bool(&self, section: &str, key: &str, default: bool) -> bool {
    //     match self.get_value(section, key) {
    //         Some(val) => {
    //             let lower_val = val.to_lowercase();
    //             match lower_val.as_str() {
    //                 "1" | "true" | "yes" | "on" | "enabled" => true,
    //                 "0" | "false" | "no" | "off" | "disabled" => false,
    //                 _ => {
    //                     warn!(
    //                         "Invalid boolean value '{}' for {}.{}, using default {}",
    //                         val,
    //                         section,
    //                         key,
    //                         default
    //                     );
    //                     default
    //                 }
    //             }
    //         }
    //         None => {
    //             debug!("Using default value {} for {}.{}", default, section, key);
    //             default
    //         }
    //     }
    // }

    // pub fn iterate_section<F>(&self, section: &str, mut callback: F) where F: FnMut(&str, &str) {
    //     if let Some(section_map) = self.sections.get(section) {
    //         for (key, value) in section_map {
    //             callback(key, value);
    //         }
    //     } else {
    //         debug!("Section '{}' not found", section);
    //     }
    // }

    // pub fn iterate_all_sections<F>(&self, mut callback: F) where F: FnMut(&str, &ConfigSection) {
    //     for (section_name, section_map) in &self.sections {
    //         callback(section_name, section_map);
    //     }
    // }

    // pub fn section_exists(&self, section: &str) -> bool {
    //     self.sections.contains_key(section)
    // }

    pub fn get_int(&self, section: &str, key: &str, default: i32) -> i32 {
        match self.get_value(section, key) {
            Some(val) =>
                match val.parse::<i32>() {
                    Ok(num) => num,
                    Err(_) => {
                        warn!(
                            "Invalid integer value '{}' for {}.{}, using default {}",
                            val,
                            section,
                            key,
                            default
                        );
                        default
                    }
                }
            None => {
                debug!("Using default value {} for {}.{}", default, section, key);
                default
            }
        }
    }

    pub fn get_bool(&self, section: &str, key: &str, default: bool) -> bool {
        match self.get_value(section, key) {
            Some(val) => {
                let lower_val = val.to_lowercase();
                match lower_val.as_str() {
                    "1" | "true" | "yes" | "on" | "enabled" => true,
                    "0" | "false" | "no" | "off" | "disabled" => false,
                    _ => {
                        warn!(
                            "Invalid boolean value '{}' for {}.{}, using default {}",
                            val,
                            section,
                            key,
                            default
                        );
                        default
                    }
                }
            }
            None => {
                debug!("Using default value {} for {}.{}", default, section, key);
                default
            }
        }
    }

    pub fn is_section_exists(&self, section: &str) -> bool {
        self.sections.contains_key(section)
    }
}

// // Callback types
// pub type ConfigEntryCallback = dyn Fn(&str, &str, &mut dyn std::any::Any) + Send + Sync;
// pub type ConfigSectionCallback = dyn Fn(&str, &ConfigSection, &mut dyn std::any::Any) + Send + Sync;

// Config loader
pub struct ConfigLoader {
    config: Config,
    path: String,
    contents: Option<String>,
}

impl ConfigLoader {
    pub fn new(path: String) -> Self {
        Self {
            config: Config::new(),
            path,
            contents: None,
        }
    }

    pub async fn load(&mut self) -> Result<ConfigLoader> {
        let binding = self.path.clone();
        let filepath = binding.trim();

        let config_path = Path::new(filepath);
        if !config_path.exists() {
            return Err(anyhow::anyhow!("Config file does not exist: {}", filepath));
        }
        if !config_path.is_file() {
            return Err(anyhow::anyhow!("Config path is not a regular file: {}", filepath));
        }

        self.contents = Some(
            fs::read_to_string(config_path).expect("Should have been able to read the file")
        );

        let contents = self.contents.as_ref().expect("Contents should be set").clone();
        self.parse_config(contents);

        Ok(self.deref_mut())
    }

    fn deref_mut(&mut self) -> ConfigLoader {
        ConfigLoader {
            config: self.config.clone(),
            path: self.path.clone(),
            contents: self.contents.clone(),
        }
    }

    fn parse_config(&mut self, contents: String) {
        let mut current_section = String::new();
        let mut line_number = 0;

        for line in contents.lines() {
            line_number += 1;
            let trimmed = line.trim();

            // Skip empty lines and comments
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
                continue;
            }

            // Check for section header: [section]
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                let section = &trimmed[1..trimmed.len() - 1];
                current_section = section.trim().to_string();
                if current_section.is_empty() {
                    warn!("Empty section name at line {}", line_number);
                }
                continue;
            }

            // Parse key-value pair
            if let Some(equals_pos) = trimmed.find('=') {
                let key = trimmed[..equals_pos].trim();
                let value = trimmed[equals_pos + 1..].trim();

                if key.is_empty() {
                    warn!("Empty key at line {}", line_number);
                    continue;
                }

                // Handle quoted values
                let value = Self::unquote_value(value);

                if current_section.is_empty() {
                    warn!("Key-value pair '{}' outside of section at line {}", key, line_number);
                    continue;
                }

                if let Err(e) = self.config.set_value(&current_section, key, &value) {
                    error!("Failed to set config value at line {}: {}", line_number, e);
                }
            } else {
                warn!("Invalid config line (no '=' found) at line {}: {}", line_number, trimmed);
            }
        }
    }

    fn unquote_value(value: &str) -> String {
        // Changed to be a static method
        let trimmed = value.trim();

        if trimmed.len() >= 2 {
            let first = trimmed.chars().next().unwrap();
            let last = trimmed.chars().last().unwrap();

            if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
                return trimmed[1..trimmed.len() - 1].to_string();
            }
        }

        trimmed.to_string()
    }

    pub fn get_config(&self) -> &Config {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_bool_defaults() {
        let mut cfg = Config::new();
        assert_eq!(cfg.get_bool("antivirus", "enabled", false), false);
        cfg.set_value("antivirus", "enabled", "true").unwrap();
        assert_eq!(cfg.get_bool("antivirus", "enabled", false), true);
    }
}
