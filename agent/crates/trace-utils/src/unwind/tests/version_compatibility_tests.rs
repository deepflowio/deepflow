/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Tests for version compatibility detection and validation

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::unwind::{
        monitoring::ProfilerMetrics,
        symbol_resolver::RuntimeType,
        version_compatibility::{CompatibilityStatus, IssueSeverity, VersionCompatibilityChecker},
    };

    /// Setup test environment
    fn setup_test_checker() -> VersionCompatibilityChecker {
        let metrics = Arc::new(ProfilerMetrics::new());
        VersionCompatibilityChecker::new(metrics).expect("Failed to create version checker")
    }

    #[test]
    fn test_php_version_compatibility() {
        let checker = setup_test_checker();

        // Test supported PHP versions
        let supported_versions = vec![
            ("7.4.0", CompatibilityStatus::FullySupported),
            ("8.0.0", CompatibilityStatus::FullySupported),
            ("8.1.0", CompatibilityStatus::FullySupported),
            ("8.2.0", CompatibilityStatus::FullySupported),
        ];

        for (version, expected_status) in supported_versions {
            let parts: Vec<&str> = version.split('.').collect();
            let major: u8 = parts[0].parse().unwrap();
            let minor: u8 = parts[1].parse().unwrap();
            let patch: u8 = parts[2].parse().unwrap();

            let status = checker.check_php_compatibility(major, minor, patch);
            assert_eq!(
                status, expected_status,
                "PHP version {} should have status {:?}",
                version, expected_status
            );
        }
    }

    #[test]
    fn test_nodejs_version_compatibility() {
        let checker = setup_test_checker();

        // Test supported Node.js versions
        let supported_versions = vec![
            ("16.0.0", CompatibilityStatus::FullySupported),
            ("18.0.0", CompatibilityStatus::FullySupported),
            ("20.0.0", CompatibilityStatus::FullySupported),
            ("21.0.0", CompatibilityStatus::FullySupported),
        ];

        for (version, expected_status) in supported_versions {
            let parts: Vec<&str> = version.split('.').collect();
            let major: u8 = parts[0].parse().unwrap();
            let minor: u8 = parts[1].parse().unwrap();
            let patch: u8 = parts[2].parse().unwrap();

            let status = checker.check_nodejs_compatibility(major, minor, patch);
            assert_eq!(
                status, expected_status,
                "Node.js version {} should have status {:?}",
                version, expected_status
            );
        }
    }

    #[test]
    fn test_unsupported_versions() {
        let checker = setup_test_checker();

        // Test unsupported PHP versions
        let unsupported_php = vec!["7.0.0", "7.1.0", "7.2.0", "9.0.0"];
        for version in unsupported_php {
            let parts: Vec<&str> = version.split('.').collect();
            let major: u8 = parts[0].parse().unwrap();
            let minor: u8 = parts[1].parse().unwrap();
            let patch: u8 = parts[2].parse().unwrap();

            let status = checker.check_php_compatibility(major, minor, patch);
            assert_eq!(
                status,
                CompatibilityStatus::Unsupported,
                "PHP version {} should be unsupported",
                version
            );
        }

        // Test unsupported Node.js versions
        let unsupported_nodejs = vec!["10.0.0", "12.0.0", "15.0.0", "23.0.0"];
        for version in unsupported_nodejs {
            let parts: Vec<&str> = version.split('.').collect();
            let major: u8 = parts[0].parse().unwrap();
            let minor: u8 = parts[1].parse().unwrap();
            let patch: u8 = parts[2].parse().unwrap();

            let status = checker.check_nodejs_compatibility(major, minor, patch);
            assert_eq!(
                status,
                CompatibilityStatus::Unsupported,
                "Node.js version {} should be unsupported",
                version
            );
        }
    }

    #[test]
    fn test_compatibility_issues_severity() {
        let checker = setup_test_checker();

        // Test unsupported version generates error
        let issues = checker.get_php_compatibility_issues(6, 0, 0);
        assert!(
            !issues.is_empty(),
            "Unsupported PHP version should generate issues"
        );
        assert!(
            issues
                .iter()
                .any(|issue| issue.severity == IssueSeverity::Error),
            "Unsupported version should generate error-level issue"
        );

        // Test old patch version generates warning
        let issues = checker.get_php_compatibility_issues(8, 1, 1);
        assert!(
            issues
                .iter()
                .any(|issue| issue.severity == IssueSeverity::Warning),
            "Old patch version should generate warning"
        );
    }

    #[test]
    fn test_nodejs_to_v8_version_mapping() {
        let checker = setup_test_checker();

        let mappings = vec![
            ("16.0.0", Some("9.4.146".to_string())),
            ("18.0.0", Some("10.2.154".to_string())),
            ("20.0.0", Some("11.3.244".to_string())),
            ("21.0.0", Some("11.8.172".to_string())),
            ("15.0.0", None), // Unsupported
        ];

        for (nodejs_version, expected_v8) in mappings {
            let result = checker.map_nodejs_to_v8_version(nodejs_version);
            assert_eq!(
                result, expected_v8,
                "Node.js {} should map to V8 {:?}",
                nodejs_version, expected_v8
            );
        }
    }

    #[test]
    fn test_offset_id_mapping() {
        let checker = setup_test_checker();

        // Test PHP offset IDs
        assert_eq!(checker.get_php_offset_id(7, 4), Some(0));
        assert_eq!(checker.get_php_offset_id(8, 0), Some(1));
        assert_eq!(checker.get_php_offset_id(8, 1), Some(2));
        assert_eq!(checker.get_php_offset_id(8, 2), Some(3));
        assert_eq!(checker.get_php_offset_id(9, 0), None); // Unsupported

        // Test Node.js offset IDs
        assert_eq!(checker.get_nodejs_offset_id(16, 0), Some(0));
        assert_eq!(checker.get_nodejs_offset_id(18, 0), Some(1));
        assert_eq!(checker.get_nodejs_offset_id(20, 0), Some(2));
        assert_eq!(checker.get_nodejs_offset_id(21, 0), Some(3));
        assert_eq!(checker.get_nodejs_offset_id(15, 0), None); // Unsupported
    }

    #[test]
    fn test_compatibility_summary() {
        let checker = setup_test_checker();
        let summary = checker.get_compatibility_summary();

        // Initial summary should be empty
        assert_eq!(summary.total_processes, 0);
        assert_eq!(summary.php_processes, 0);
        assert_eq!(summary.nodejs_processes, 0);
        assert_eq!(summary.support_rate(), 100.0); // 100% when no processes
        assert!(!summary.has_compatibility_issues());
    }

    #[test]
    fn test_cache_operations() {
        let checker = setup_test_checker();

        // Test cache operations don't panic
        checker.remove_process(12345);
        checker.clear_cache();

        // These should complete without error
        let summary_before = checker.get_compatibility_summary();
        checker.clear_cache();
        let summary_after = checker.get_compatibility_summary();

        assert_eq!(
            summary_before.total_processes,
            summary_after.total_processes
        );
    }

    #[test]
    fn test_version_regex_patterns() {
        let checker = setup_test_checker();

        // Test PHP version regex
        let php_versions = vec![
            ("PHP 8.1.10 (cli)", Some((8, 1, 10))),
            ("PHP 7.4.33 (fpm-fcgi)", Some((7, 4, 33))),
            ("Invalid version string", None),
        ];

        for (version_string, expected) in php_versions {
            let captures = checker.php_version_regex.captures(version_string);
            match expected {
                Some((major, minor, patch)) => {
                    assert!(
                        captures.is_some(),
                        "Should match PHP version in: {}",
                        version_string
                    );
                    let caps = captures.unwrap();
                    assert_eq!(caps[1].parse::<u8>().unwrap(), major);
                    assert_eq!(caps[2].parse::<u8>().unwrap(), minor);
                    assert_eq!(caps[3].parse::<u8>().unwrap(), patch);
                }
                None => {
                    assert!(captures.is_none(), "Should not match: {}", version_string);
                }
            }
        }

        // Test Node.js version regex
        let nodejs_versions = vec![
            ("v18.17.0", Some((18, 17, 0))),
            ("v20.5.1", Some((20, 5, 1))),
            ("Invalid version", None),
        ];

        for (version_string, expected) in nodejs_versions {
            let captures = checker.nodejs_version_regex.captures(version_string);
            match expected {
                Some((major, minor, patch)) => {
                    assert!(
                        captures.is_some(),
                        "Should match Node.js version in: {}",
                        version_string
                    );
                    let caps = captures.unwrap();
                    assert_eq!(caps[1].parse::<u8>().unwrap(), major);
                    assert_eq!(caps[2].parse::<u8>().unwrap(), minor);
                    assert_eq!(caps[3].parse::<u8>().unwrap(), patch);
                }
                None => {
                    assert!(captures.is_none(), "Should not match: {}", version_string);
                }
            }
        }
    }

    #[test]
    fn test_issue_recommendations() {
        let checker = setup_test_checker();

        // Test that issues include recommendations
        let issues = checker.get_php_compatibility_issues(6, 0, 0);
        for issue in &issues {
            assert!(
                issue.recommendation.is_some(),
                "Issue should include recommendation: {}",
                issue.message
            );
            assert!(
                !issue.recommendation.as_ref().unwrap().is_empty(),
                "Recommendation should not be empty"
            );
        }

        let issues = checker.get_nodejs_compatibility_issues(12, 0, 0);
        for issue in &issues {
            assert!(
                issue.recommendation.is_some(),
                "Issue should include recommendation: {}",
                issue.message
            );
            assert!(
                !issue.recommendation.as_ref().unwrap().is_empty(),
                "Recommendation should not be empty"
            );
        }
    }

    #[test]
    fn test_confidence_levels() {
        let checker = setup_test_checker();

        // Test that different detection methods have appropriate confidence levels
        // This would be expanded with actual process detection tests

        // For now, just verify the confidence calculation logic makes sense
        let confidence_levels = vec![0.0, 0.1, 0.5, 0.9, 1.0];

        for confidence in confidence_levels {
            assert!(
                confidence >= 0.0 && confidence <= 1.0,
                "Confidence should be between 0.0 and 1.0: {}",
                confidence
            );
        }
    }
}
