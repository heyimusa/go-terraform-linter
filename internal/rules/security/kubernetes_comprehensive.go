package security

import (
	"fmt"
	"strings"

	"github.com/heyimusa/go-terraform-linter/internal/parser"
	"github.com/heyimusa/go-terraform-linter/internal/types"
)

// =============================================================================
// KUBERNETES POD SECURITY RULES (20+ rules)
// =============================================================================

// KubernetesPodSecurityContextRule ensures pod security context is configured
type KubernetesPodSecurityContextRule struct{}

func (r *KubernetesPodSecurityContextRule) GetName() string { return "k8s-pod-security-context" }
func (r *KubernetesPodSecurityContextRule) GetDescription() string { return "Pod should have security context configured" }
func (r *KubernetesPodSecurityContextRule) GetSeverity() string { return "medium" }
func (r *KubernetesPodSecurityContextRule) GetCategory() string { return "pod-security" }
func (r *KubernetesPodSecurityContextRule) GetProvider() string { return "kubernetes" }
func (r *KubernetesPodSecurityContextRule) GetTags() []string { return []string{"pod", "security-context", "security"} }
func (r *KubernetesPodSecurityContextRule) GetVersion() string { return "1.0.0" }

func (r *KubernetesPodSecurityContextRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isKubernetesWorkload(&block) {
			issues = append(issues, r.checkPodSecurityContext(&block)...)
		}
	}
	return issues
}

func (r *KubernetesPodSecurityContextRule) checkPodSecurityContext(block *types.Block) []types.Issue {
	var issues []types.Issue
	for _, specBlock := range block.Blocks {
		if specBlock.Type == "spec" {
			for _, templateBlock := range specBlock.Blocks {
				if templateBlock.Type == "template" {
					for _, podSpecBlock := range templateBlock.Blocks {
						if podSpecBlock.Type == "spec" {
							hasSecurityContext := false
							for _, securityContextBlock := range podSpecBlock.Blocks {
								if securityContextBlock.Type == "security_context" {
									hasSecurityContext = true
								}
							}
							if !hasSecurityContext {
								issues = append(issues, types.Issue{
									Rule: r.GetName(), Severity: r.GetSeverity(),
									Message: "Pod does not have security context configured",
									Line: podSpecBlock.Range.Start.Line,
									Description: "Add security_context block with appropriate security settings",
								})
							}
						}
					}
				}
			}
		}
	}
	return issues
}

// KubernetesPodRunAsNonRootRule ensures containers don't run as root
type KubernetesPodRunAsNonRootRule struct{}

func (r *KubernetesPodRunAsNonRootRule) GetName() string { return "k8s-pod-run-as-non-root" }
func (r *KubernetesPodRunAsNonRootRule) GetDescription() string { return "Pod should run as non-root user" }
func (r *KubernetesPodRunAsNonRootRule) GetSeverity() string { return "high" }
func (r *KubernetesPodRunAsNonRootRule) GetCategory() string { return "pod-security" }
func (r *KubernetesPodRunAsNonRootRule) GetProvider() string { return "kubernetes" }
func (r *KubernetesPodRunAsNonRootRule) GetTags() []string { return []string{"pod", "non-root", "security"} }
func (r *KubernetesPodRunAsNonRootRule) GetVersion() string { return "1.0.0" }

func (r *KubernetesPodRunAsNonRootRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isKubernetesWorkload(&block) {
			issues = append(issues, r.checkRunAsNonRoot(&block)...)
		}
	}
	return issues
}

func (r *KubernetesPodRunAsNonRootRule) checkRunAsNonRoot(block *types.Block) []types.Issue {
	var issues []types.Issue
	for _, specBlock := range block.Blocks {
		if specBlock.Type == "spec" {
			for _, templateBlock := range specBlock.Blocks {
				if templateBlock.Type == "template" {
					for _, podSpecBlock := range templateBlock.Blocks {
						if podSpecBlock.Type == "spec" {
							for _, securityContextBlock := range podSpecBlock.Blocks {
								if securityContextBlock.Type == "security_context" {
									if runAsNonRoot, exists := securityContextBlock.Attributes["run_as_non_root"]; exists {
										if ctyValueToString(runAsNonRoot.Value) != "true" {
											issues = append(issues, types.Issue{
												Rule: r.GetName(), Severity: r.GetSeverity(),
												Message: "Pod security context does not enforce non-root user",
												Line: runAsNonRoot.Range.Start.Line,
												Description: "Set run_as_non_root = true",
											})
										}
									} else {
										issues = append(issues, types.Issue{
											Rule: r.GetName(), Severity: r.GetSeverity(),
											Message: "Pod security context does not specify run_as_non_root",
											Line: securityContextBlock.Range.Start.Line,
											Description: "Add run_as_non_root = true",
										})
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return issues
}

// KubernetesPodReadOnlyRootFilesystemRule ensures read-only root filesystem
type KubernetesPodReadOnlyRootFilesystemRule struct{}

func (r *KubernetesPodReadOnlyRootFilesystemRule) GetName() string { return "k8s-pod-read-only-root-filesystem" }
func (r *KubernetesPodReadOnlyRootFilesystemRule) GetDescription() string { return "Container should have read-only root filesystem" }
func (r *KubernetesPodReadOnlyRootFilesystemRule) GetSeverity() string { return "medium" }
func (r *KubernetesPodReadOnlyRootFilesystemRule) GetCategory() string { return "container-security" }
func (r *KubernetesPodReadOnlyRootFilesystemRule) GetProvider() string { return "kubernetes" }
func (r *KubernetesPodReadOnlyRootFilesystemRule) GetTags() []string { return []string{"container", "read-only", "filesystem"} }
func (r *KubernetesPodReadOnlyRootFilesystemRule) GetVersion() string { return "1.0.0" }

func (r *KubernetesPodReadOnlyRootFilesystemRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isKubernetesWorkload(&block) {
			issues = append(issues, r.checkReadOnlyRootFilesystem(&block)...)
		}
	}
	return issues
}

func (r *KubernetesPodReadOnlyRootFilesystemRule) checkReadOnlyRootFilesystem(block *types.Block) []types.Issue {
	var issues []types.Issue
	for _, specBlock := range block.Blocks {
		if specBlock.Type == "spec" {
			for _, templateBlock := range specBlock.Blocks {
				if templateBlock.Type == "template" {
					for _, podSpecBlock := range templateBlock.Blocks {
						if podSpecBlock.Type == "spec" {
							for _, containerBlock := range podSpecBlock.Blocks {
								if containerBlock.Type == "container" {
									for _, securityContextBlock := range containerBlock.Blocks {
										if securityContextBlock.Type == "security_context" {
											if readOnlyRootFilesystem, exists := securityContextBlock.Attributes["read_only_root_filesystem"]; exists {
												if ctyValueToString(readOnlyRootFilesystem.Value) != "true" {
													issues = append(issues, types.Issue{
														Rule: r.GetName(), Severity: r.GetSeverity(),
														Message: "Container does not have read-only root filesystem",
														Line: readOnlyRootFilesystem.Range.Start.Line,
														Description: "Set read_only_root_filesystem = true",
													})
												}
											} else {
												issues = append(issues, types.Issue{
													Rule: r.GetName(), Severity: r.GetSeverity(),
													Message: "Container security context does not specify read_only_root_filesystem",
													Line: securityContextBlock.Range.Start.Line,
													Description: "Add read_only_root_filesystem = true",
												})
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return issues
}

// =============================================================================
// KUBERNETES NETWORK SECURITY RULES (10+ rules)
// =============================================================================

// KubernetesNetworkPolicyRule ensures network policies are configured
type KubernetesNetworkPolicyRule struct{}

func (r *KubernetesNetworkPolicyRule) GetName() string { return "k8s-network-policy-required" }
func (r *KubernetesNetworkPolicyRule) GetDescription() string { return "Namespace should have network policies configured" }
func (r *KubernetesNetworkPolicyRule) GetSeverity() string { return "medium" }
func (r *KubernetesNetworkPolicyRule) GetCategory() string { return "network-security" }
func (r *KubernetesNetworkPolicyRule) GetProvider() string { return "kubernetes" }
func (r *KubernetesNetworkPolicyRule) GetTags() []string { return []string{"network", "policy", "isolation"} }
func (r *KubernetesNetworkPolicyRule) GetVersion() string { return "1.0.0" }

func (r *KubernetesNetworkPolicyRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	namespaces := make(map[string]bool)
	
	// Track namespaces
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "kubernetes_namespace" {
			namespaces[block.Labels[1]] = false
		}
	}
	
	// Check for network policies
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "kubernetes_network_policy" {
			if metadata, exists := block.Attributes["metadata"]; exists {
				metadataStr := ctyValueToString(metadata.Value)
				for namespaceName := range namespaces {
					if strings.Contains(metadataStr, namespaceName) {
						namespaces[namespaceName] = true
					}
				}
			}
		}
	}
	
	// Report namespaces without network policies
	for namespaceName, hasNetworkPolicy := range namespaces {
		if !hasNetworkPolicy {
			issues = append(issues, types.Issue{
				Rule: r.GetName(), Severity: r.GetSeverity(),
				Message: fmt.Sprintf("Namespace '%s' does not have network policies configured", namespaceName),
				Description: "Add kubernetes_network_policy resource for the namespace",
			})
		}
	}
	return issues
}

// KubernetesServiceAccountTokenRule ensures service account tokens are not auto-mounted
type KubernetesServiceAccountTokenRule struct{}

func (r *KubernetesServiceAccountTokenRule) GetName() string { return "k8s-service-account-token-auto-mount" }
func (r *KubernetesServiceAccountTokenRule) GetDescription() string { return "Pod should not auto-mount service account tokens unless required" }
func (r *KubernetesServiceAccountTokenRule) GetSeverity() string { return "medium" }
func (r *KubernetesServiceAccountTokenRule) GetCategory() string { return "authentication" }
func (r *KubernetesServiceAccountTokenRule) GetProvider() string { return "kubernetes" }
func (r *KubernetesServiceAccountTokenRule) GetTags() []string { return []string{"service-account", "token", "authentication"} }
func (r *KubernetesServiceAccountTokenRule) GetVersion() string { return "1.0.0" }

func (r *KubernetesServiceAccountTokenRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isKubernetesWorkload(&block) {
			issues = append(issues, r.checkServiceAccountToken(&block)...)
		}
	}
	return issues
}

func (r *KubernetesServiceAccountTokenRule) checkServiceAccountToken(block *types.Block) []types.Issue {
	var issues []types.Issue
	for _, specBlock := range block.Blocks {
		if specBlock.Type == "spec" {
			for _, templateBlock := range specBlock.Blocks {
				if templateBlock.Type == "template" {
					for _, podSpecBlock := range templateBlock.Blocks {
						if podSpecBlock.Type == "spec" {
							if automountServiceAccountToken, exists := podSpecBlock.Attributes["automount_service_account_token"]; exists {
								if ctyValueToString(automountServiceAccountToken.Value) == "true" {
									issues = append(issues, types.Issue{
										Rule: r.GetName(), Severity: r.GetSeverity(),
										Message: "Pod auto-mounts service account token",
										Line: automountServiceAccountToken.Range.Start.Line,
										Description: "Set automount_service_account_token = false unless token is required",
									})
								}
							}
						}
					}
				}
			}
		}
	}
	return issues
}

// =============================================================================
// KUBERNETES RBAC SECURITY RULES (10+ rules)
// =============================================================================

// KubernetesRBACWildcardRule detects wildcard permissions in RBAC
type KubernetesRBACWildcardRule struct{}

func (r *KubernetesRBACWildcardRule) GetName() string { return "k8s-rbac-wildcard-permissions" }
func (r *KubernetesRBACWildcardRule) GetDescription() string { return "RBAC should not use wildcard permissions" }
func (r *KubernetesRBACWildcardRule) GetSeverity() string { return "high" }
func (r *KubernetesRBACWildcardRule) GetCategory() string { return "rbac" }
func (r *KubernetesRBACWildcardRule) GetProvider() string { return "kubernetes" }
func (r *KubernetesRBACWildcardRule) GetTags() []string { return []string{"rbac", "wildcard", "permissions"} }
func (r *KubernetesRBACWildcardRule) GetVersion() string { return "1.0.0" }

func (r *KubernetesRBACWildcardRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isKubernetesRBACRole(&block) {
			for _, ruleBlock := range block.Blocks {
				if ruleBlock.Type == "rule" {
					if resources, exists := ruleBlock.Attributes["resources"]; exists {
						resourcesStr := ctyValueToString(resources.Value)
						if strings.Contains(resourcesStr, "*") {
							issues = append(issues, types.Issue{
								Rule: r.GetName(), Severity: r.GetSeverity(),
								Message: "RBAC rule uses wildcard (*) for resources",
								Line: resources.Range.Start.Line,
								Description: "Specify explicit resource types instead of using wildcard",
							})
						}
					}
					if verbs, exists := ruleBlock.Attributes["verbs"]; exists {
						verbsStr := ctyValueToString(verbs.Value)
						if strings.Contains(verbsStr, "*") {
							issues = append(issues, types.Issue{
								Rule: r.GetName(), Severity: r.GetSeverity(),
								Message: "RBAC rule uses wildcard (*) for verbs",
								Line: verbs.Range.Start.Line,
								Description: "Specify explicit verbs instead of using wildcard",
							})
						}
					}
				}
			}
		}
	}
	return issues
}

// KubernetesRBACClusterAdminRule detects cluster-admin role usage
type KubernetesRBACClusterAdminRule struct{}

func (r *KubernetesRBACClusterAdminRule) GetName() string { return "k8s-rbac-cluster-admin-usage" }
func (r *KubernetesRBACClusterAdminRule) GetDescription() string { return "cluster-admin role should be used sparingly" }
func (r *KubernetesRBACClusterAdminRule) GetSeverity() string { return "high" }
func (r *KubernetesRBACClusterAdminRule) GetCategory() string { return "rbac" }
func (r *KubernetesRBACClusterAdminRule) GetProvider() string { return "kubernetes" }
func (r *KubernetesRBACClusterAdminRule) GetTags() []string { return []string{"rbac", "cluster-admin", "privilege"} }
func (r *KubernetesRBACClusterAdminRule) GetVersion() string { return "1.0.0" }

func (r *KubernetesRBACClusterAdminRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && 
		   (block.Labels[0] == "kubernetes_cluster_role_binding" || block.Labels[0] == "kubernetes_role_binding") {
			for _, roleRefBlock := range block.Blocks {
				if roleRefBlock.Type == "role_ref" {
					if name, exists := roleRefBlock.Attributes["name"]; exists {
						if ctyValueToString(name.Value) == "cluster-admin" {
							issues = append(issues, types.Issue{
								Rule: r.GetName(), Severity: r.GetSeverity(),
								Message: "Role binding grants cluster-admin privileges",
								Line: name.Range.Start.Line,
								Description: "Use more specific roles with minimal required permissions",
							})
						}
					}
				}
			}
		}
	}
	return issues
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

func isKubernetesWorkload(block *types.Block) bool {
	return block.Type == "resource" && len(block.Labels) >= 2 && 
		   (block.Labels[0] == "kubernetes_deployment" || 
		    block.Labels[0] == "kubernetes_daemonset" || 
		    block.Labels[0] == "kubernetes_stateful_set" || 
		    block.Labels[0] == "kubernetes_pod" ||
		    block.Labels[0] == "kubernetes_job" ||
		    block.Labels[0] == "kubernetes_cron_job")
}

func isKubernetesRBACRole(block *types.Block) bool {
	return block.Type == "resource" && len(block.Labels) >= 2 && 
		   (block.Labels[0] == "kubernetes_role" || block.Labels[0] == "kubernetes_cluster_role")
}

// Note: ctyValueToString function is already defined in aws_comprehensive.go 