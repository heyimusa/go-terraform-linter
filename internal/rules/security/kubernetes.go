package security

import (
	"fmt"
	"strings"

	"github.com/heyimusa/go-terraform-linter/internal/parser"
	"github.com/heyimusa/go-terraform-linter/internal/types"
)

// Kubernetes Security Rules Implementation

// KubernetesPrivilegedContainerRule detects privileged containers
type KubernetesPrivilegedContainerRule struct{}

func (r *KubernetesPrivilegedContainerRule) GetName() string { return "K8S_PRIVILEGED_CONTAINER" }
func (r *KubernetesPrivilegedContainerRule) GetDescription() string {
	return "Detects Kubernetes containers running in privileged mode"
}
func (r *KubernetesPrivilegedContainerRule) GetSeverity() string { return "critical" }
func (r *KubernetesPrivilegedContainerRule) GetCategory() string { return "container-security" }
func (r *KubernetesPrivilegedContainerRule) GetProvider() string { return "kubernetes" }
func (r *KubernetesPrivilegedContainerRule) GetTags() []string { return []string{"security", "container", "privilege"} }
func (r *KubernetesPrivilegedContainerRule) GetVersion() string { return "1.0.0" }

func (r *KubernetesPrivilegedContainerRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 {
			resourceType := block.Labels[0]

			// Check Kubernetes deployments, daemonsets, statefulsets
			if resourceType == "kubernetes_deployment" || resourceType == "kubernetes_daemonset" || 
			   resourceType == "kubernetes_stateful_set" {
				issues = append(issues, r.checkPodSpec(block)...)
			}

			// Check Kubernetes pods directly
			if resourceType == "kubernetes_pod" {
				issues = append(issues, r.checkPodSpec(block)...)
			}
		}
	}

	return issues
}

func (r *KubernetesPrivilegedContainerRule) checkPodSpec(block *types.Block) []types.Issue {
	var issues []types.Issue

	// Navigate through the nested structure to find containers
	for _, specBlock := range block.Blocks {
		if specBlock.Type == "spec" {
			for _, templateBlock := range specBlock.Blocks {
				if templateBlock.Type == "template" {
					for _, podSpecBlock := range templateBlock.Blocks {
						if podSpecBlock.Type == "spec" {
							issues = append(issues, r.checkContainers(podSpecBlock)...)
						}
					}
				}
				// Direct spec for pods
				if templateBlock.Type == "container" {
					issues = append(issues, r.checkContainer(templateBlock)...)
				}
			}
		}
	}

	return issues
}

func (r *KubernetesPrivilegedContainerRule) checkContainers(specBlock *types.Block) []types.Issue {
	var issues []types.Issue

	for _, containerBlock := range specBlock.Blocks {
		if containerBlock.Type == "container" {
			issues = append(issues, r.checkContainer(containerBlock)...)
		}
	}

	return issues
}

func (r *KubernetesPrivilegedContainerRule) checkContainer(containerBlock *types.Block) []types.Issue {
	var issues []types.Issue

	for _, securityContextBlock := range containerBlock.Blocks {
		if securityContextBlock.Type == "security_context" {
			if privileged, exists := securityContextBlock.Attributes["privileged"]; exists {
				if strings.Contains(ctyValueToString(privileged.Value), "true") {
					issues = append(issues, types.Issue{
						Rule:        r.GetName(),
						Message:     "Container is running in privileged mode",
						Description: "Privileged containers have access to all host resources and should be avoided",
						Severity:    r.GetSeverity(),
						Line:        privileged.Range.Start.Line,
					})
				}
			}
		}
	}

	return issues
}

// KubernetesRootUserRule detects containers running as root
type KubernetesRootUserRule struct{}

func (r *KubernetesRootUserRule) GetName() string { return "K8S_ROOT_USER" }
func (r *KubernetesRootUserRule) GetDescription() string {
	return "Detects Kubernetes containers running as root user"
}
func (r *KubernetesRootUserRule) GetSeverity() string { return "high" }
func (r *KubernetesRootUserRule) GetCategory() string { return "container-security" }
func (r *KubernetesRootUserRule) GetProvider() string { return "kubernetes" }
func (r *KubernetesRootUserRule) GetTags() []string { return []string{"security", "container", "user"} }
func (r *KubernetesRootUserRule) GetVersion() string { return "1.0.0" }

func (r *KubernetesRootUserRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 {
			resourceType := block.Labels[0]

			if resourceType == "kubernetes_deployment" || resourceType == "kubernetes_daemonset" || 
			   resourceType == "kubernetes_stateful_set" || resourceType == "kubernetes_pod" {
				issues = append(issues, r.checkForRootUser(block)...)
			}
		}
	}

	return issues
}

func (r *KubernetesRootUserRule) checkForRootUser(block *types.Block) []types.Issue {
	var issues []types.Issue

	// Similar navigation pattern as privileged container check
	for _, specBlock := range block.Blocks {
		if specBlock.Type == "spec" {
			for _, templateBlock := range specBlock.Blocks {
				if templateBlock.Type == "template" {
					for _, podSpecBlock := range templateBlock.Blocks {
						if podSpecBlock.Type == "spec" {
							issues = append(issues, r.checkPodSpecForRootUser(podSpecBlock)...)
						}
					}
				}
				if templateBlock.Type == "container" {
					issues = append(issues, r.checkContainerForRootUser(templateBlock)...)
				}
			}
		}
	}

	return issues
}

func (r *KubernetesRootUserRule) checkPodSpecForRootUser(specBlock *types.Block) []types.Issue {
	var issues []types.Issue

	// Check pod-level security context
	for _, securityContextBlock := range specBlock.Blocks {
		if securityContextBlock.Type == "security_context" {
			if runAsUser, exists := securityContextBlock.Attributes["run_as_user"]; exists {
				if ctyValueToString(runAsUser.Value) == "0" {
					issues = append(issues, types.Issue{
						Rule:        r.GetName(),
						Message:     "Pod is configured to run as root user (UID 0)",
						Description: "Containers should run as non-root users for better security",
						Severity:    r.GetSeverity(),
						Line:        runAsUser.Range.Start.Line,
					})
				}
			}
		}
	}

	// Check container-level security context
	for _, containerBlock := range specBlock.Blocks {
		if containerBlock.Type == "container" {
			issues = append(issues, r.checkContainerForRootUser(containerBlock)...)
		}
	}

	return issues
}

func (r *KubernetesRootUserRule) checkContainerForRootUser(containerBlock *types.Block) []types.Issue {
	var issues []types.Issue

	for _, securityContextBlock := range containerBlock.Blocks {
		if securityContextBlock.Type == "security_context" {
			if runAsUser, exists := securityContextBlock.Attributes["run_as_user"]; exists {
				if ctyValueToString(runAsUser.Value) == "0" {
					issues = append(issues, types.Issue{
						Rule:        r.GetName(),
						Message:     "Container is configured to run as root user (UID 0)",
						Description: "Containers should run as non-root users for better security",
						Severity:    r.GetSeverity(),
						Line:        runAsUser.Range.Start.Line,
					})
				}
			}
		}
	}

	return issues
}

// KubernetesCapabilitiesRule detects dangerous Linux capabilities
type KubernetesCapabilitiesRule struct{}

func (r *KubernetesCapabilitiesRule) GetName() string { return "K8S_DANGEROUS_CAPABILITIES" }
func (r *KubernetesCapabilitiesRule) GetDescription() string {
	return "Detects Kubernetes containers with dangerous Linux capabilities"
}
func (r *KubernetesCapabilitiesRule) GetSeverity() string { return "high" }
func (r *KubernetesCapabilitiesRule) GetCategory() string { return "container-security" }
func (r *KubernetesCapabilitiesRule) GetProvider() string { return "kubernetes" }
func (r *KubernetesCapabilitiesRule) GetTags() []string { return []string{"security", "container", "capabilities"} }
func (r *KubernetesCapabilitiesRule) GetVersion() string { return "1.0.0" }

func (r *KubernetesCapabilitiesRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	dangerousCapabilities := []string{
		"SYS_ADMIN", "NET_ADMIN", "SYS_TIME", "SYS_MODULE", 
		"SYS_RAWIO", "SYS_PTRACE", "DAC_OVERRIDE", "DAC_READ_SEARCH",
	}

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 {
			resourceType := block.Labels[0]

			if resourceType == "kubernetes_deployment" || resourceType == "kubernetes_daemonset" || 
			   resourceType == "kubernetes_stateful_set" || resourceType == "kubernetes_pod" {
				issues = append(issues, r.checkCapabilities(block, dangerousCapabilities)...)
			}
		}
	}

	return issues
}

func (r *KubernetesCapabilitiesRule) checkCapabilities(block *types.Block, dangerousCapabilities []string) []types.Issue {
	var issues []types.Issue

	// Navigate to security context and check capabilities
	for _, specBlock := range block.Blocks {
		if specBlock.Type == "spec" {
			for _, templateBlock := range specBlock.Blocks {
				if templateBlock.Type == "template" {
					for _, podSpecBlock := range templateBlock.Blocks {
						if podSpecBlock.Type == "spec" {
							for _, containerBlock := range podSpecBlock.Blocks {
								if containerBlock.Type == "container" {
									issues = append(issues, r.checkContainerCapabilities(containerBlock, dangerousCapabilities)...)
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

func (r *KubernetesCapabilitiesRule) checkContainerCapabilities(containerBlock *types.Block, dangerousCapabilities []string) []types.Issue {
	var issues []types.Issue

	for _, securityContextBlock := range containerBlock.Blocks {
		if securityContextBlock.Type == "security_context" {
			for _, capabilitiesBlock := range securityContextBlock.Blocks {
				if capabilitiesBlock.Type == "capabilities" {
					if add, exists := capabilitiesBlock.Attributes["add"]; exists {
						addStr := ctyValueToString(add.Value)
						for _, dangerousCap := range dangerousCapabilities {
							if strings.Contains(addStr, dangerousCap) {
								issues = append(issues, types.Issue{
									Rule:        r.GetName(),
									Message:     fmt.Sprintf("Container adds dangerous capability: %s", dangerousCap),
									Description: "Avoid adding dangerous Linux capabilities to containers",
									Severity:    r.GetSeverity(),
									Line:        add.Range.Start.Line,
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

// KubernetesHostNetworkRule detects containers using host network
type KubernetesHostNetworkRule struct{}

func (r *KubernetesHostNetworkRule) GetName() string { return "K8S_HOST_NETWORK" }
func (r *KubernetesHostNetworkRule) GetDescription() string {
	return "Detects Kubernetes pods using host network"
}
func (r *KubernetesHostNetworkRule) GetSeverity() string { return "high" }
func (r *KubernetesHostNetworkRule) GetCategory() string { return "network-security" }
func (r *KubernetesHostNetworkRule) GetProvider() string { return "kubernetes" }
func (r *KubernetesHostNetworkRule) GetTags() []string { return []string{"security", "network", "host"} }
func (r *KubernetesHostNetworkRule) GetVersion() string { return "1.0.0" }

func (r *KubernetesHostNetworkRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 {
			resourceType := block.Labels[0]

			if resourceType == "kubernetes_deployment" || resourceType == "kubernetes_daemonset" || 
			   resourceType == "kubernetes_stateful_set" || resourceType == "kubernetes_pod" {
				issues = append(issues, r.checkHostNetwork(block)...)
			}
		}
	}

	return issues
}

func (r *KubernetesHostNetworkRule) checkHostNetwork(block *types.Block) []types.Issue {
	var issues []types.Issue

	for _, specBlock := range block.Blocks {
		if specBlock.Type == "spec" {
			for _, templateBlock := range specBlock.Blocks {
				if templateBlock.Type == "template" {
					for _, podSpecBlock := range templateBlock.Blocks {
						if podSpecBlock.Type == "spec" {
							if hostNetwork, exists := podSpecBlock.Attributes["host_network"]; exists {
								if strings.Contains(ctyValueToString(hostNetwork.Value), "true") {
									issues = append(issues, types.Issue{
										Rule:        r.GetName(),
										Message:     "Pod is using host network",
										Description: "Avoid using host network as it bypasses network policies and isolation",
										Severity:    r.GetSeverity(),
										Line:        hostNetwork.Range.Start.Line,
									})
								}
							}
						}
					}
				}
				// Direct spec check for pods
				if hostNetwork, exists := templateBlock.Attributes["host_network"]; exists {
					if strings.Contains(ctyValueToString(hostNetwork.Value), "true") {
						issues = append(issues, types.Issue{
							Rule:        r.GetName(),
							Message:     "Pod is using host network",
							Description: "Avoid using host network as it bypasses network policies and isolation",
							Severity:    r.GetSeverity(),
							Line:        hostNetwork.Range.Start.Line,
						})
					}
				}
			}
		}
	}

	return issues
}

// KubernetesSecretsInEnvRule detects secrets exposed as environment variables
type KubernetesSecretsInEnvRule struct{}

func (r *KubernetesSecretsInEnvRule) GetName() string { return "K8S_SECRETS_IN_ENV" }
func (r *KubernetesSecretsInEnvRule) GetDescription() string {
	return "Detects Kubernetes secrets exposed as environment variables"
}
func (r *KubernetesSecretsInEnvRule) GetSeverity() string { return "medium" }
func (r *KubernetesSecretsInEnvRule) GetCategory() string { return "secrets" }
func (r *KubernetesSecretsInEnvRule) GetProvider() string { return "kubernetes" }
func (r *KubernetesSecretsInEnvRule) GetTags() []string { return []string{"security", "secrets", "environment"} }
func (r *KubernetesSecretsInEnvRule) GetVersion() string { return "1.0.0" }

func (r *KubernetesSecretsInEnvRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	secretKeywords := []string{"password", "secret", "key", "token", "api_key", "private_key"}

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 {
			resourceType := block.Labels[0]

			if resourceType == "kubernetes_deployment" || resourceType == "kubernetes_daemonset" || 
			   resourceType == "kubernetes_stateful_set" || resourceType == "kubernetes_pod" {
				issues = append(issues, r.checkEnvironmentVariables(block, secretKeywords)...)
			}
		}
	}

	return issues
}

func (r *KubernetesSecretsInEnvRule) checkEnvironmentVariables(block *types.Block, secretKeywords []string) []types.Issue {
	var issues []types.Issue

	for _, specBlock := range block.Blocks {
		if specBlock.Type == "spec" {
			for _, templateBlock := range specBlock.Blocks {
				if templateBlock.Type == "template" {
					for _, podSpecBlock := range templateBlock.Blocks {
						if podSpecBlock.Type == "spec" {
							for _, containerBlock := range podSpecBlock.Blocks {
								if containerBlock.Type == "container" {
									issues = append(issues, r.checkContainerEnv(containerBlock, secretKeywords)...)
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

func (r *KubernetesSecretsInEnvRule) checkContainerEnv(containerBlock *types.Block, secretKeywords []string) []types.Issue {
	var issues []types.Issue

	for _, envBlock := range containerBlock.Blocks {
		if envBlock.Type == "env" {
			if name, exists := envBlock.Attributes["name"]; exists {
				nameStr := strings.ToLower(ctyValueToString(name.Value))
				for _, keyword := range secretKeywords {
					if strings.Contains(nameStr, keyword) {
						// Check if it's using a secret reference (which is good) or plain value (which is bad)
						if value, exists := envBlock.Attributes["value"]; exists && ctyValueToString(value.Value) != "" {
							issues = append(issues, types.Issue{
								Rule:        r.GetName(),
								Message:     fmt.Sprintf("Potential secret '%s' exposed as plain environment variable", nameStr),
								Description: "Use Kubernetes secrets and secret references instead of plain text",
								Severity:    r.GetSeverity(),
								Line:        value.Range.Start.Line,
							})
						}
					}
				}
			}
		}
	}

	return issues
}

// KubernetesResourceLimitsRule detects containers without resource limits
type KubernetesResourceLimitsRule struct{}

func (r *KubernetesResourceLimitsRule) GetName() string { return "K8S_NO_RESOURCE_LIMITS" }
func (r *KubernetesResourceLimitsRule) GetDescription() string {
	return "Detects Kubernetes containers without resource limits"
}
func (r *KubernetesResourceLimitsRule) GetSeverity() string { return "medium" }
func (r *KubernetesResourceLimitsRule) GetCategory() string { return "resource-management" }
func (r *KubernetesResourceLimitsRule) GetProvider() string { return "kubernetes" }
func (r *KubernetesResourceLimitsRule) GetTags() []string { return []string{"security", "resources", "limits"} }
func (r *KubernetesResourceLimitsRule) GetVersion() string { return "1.0.0" }

func (r *KubernetesResourceLimitsRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 {
			resourceType := block.Labels[0]

			if resourceType == "kubernetes_deployment" || resourceType == "kubernetes_daemonset" || 
			   resourceType == "kubernetes_stateful_set" || resourceType == "kubernetes_pod" {
				issues = append(issues, r.checkResourceLimits(block)...)
			}
		}
	}

	return issues
}

func (r *KubernetesResourceLimitsRule) checkResourceLimits(block *types.Block) []types.Issue {
	var issues []types.Issue

	for _, specBlock := range block.Blocks {
		if specBlock.Type == "spec" {
			for _, templateBlock := range specBlock.Blocks {
				if templateBlock.Type == "template" {
					for _, podSpecBlock := range templateBlock.Blocks {
						if podSpecBlock.Type == "spec" {
							for _, containerBlock := range podSpecBlock.Blocks {
								if containerBlock.Type == "container" {
									issues = append(issues, r.checkContainerResources(containerBlock)...)
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

func (r *KubernetesResourceLimitsRule) checkContainerResources(containerBlock *types.Block) []types.Issue {
	var issues []types.Issue

	hasResourceLimits := false
	for _, resourceBlock := range containerBlock.Blocks {
		if resourceBlock.Type == "resources" {
			for _, limitsBlock := range resourceBlock.Blocks {
				if limitsBlock.Type == "limits" {
					hasResourceLimits = true
					break
				}
			}
		}
	}

	if !hasResourceLimits {
		issues = append(issues, types.Issue{
			Rule:        r.GetName(),
			Message:     "Container does not have resource limits defined",
			Description: "Define CPU and memory limits to prevent resource exhaustion attacks",
			Severity:    r.GetSeverity(),
			Line:        containerBlock.Range.Start.Line,
		})
	}

	return issues
} 