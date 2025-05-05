// Project: traefik-consul-registrator
// A lightweight service that automatically registers Traefik-exposed Docker containers in Consul

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/hashicorp/consul/api"
)

var (
	version           = "0.1.0"
	consulAPI         = flag.String("consul-api", "http://127.0.0.1:8500", "Consul API URL")
	syncInterval      = flag.Int("sync-interval", 60, "Interval in seconds between sync operations")
	internalMode      = flag.Bool("internal", false, "Use internal container ports instead of published ones")
	cleanup           = flag.Bool("cleanup", false, "Clean up stale services on startup")
	networksPriority  = flag.String("networks-priority", "", "Prioritize networks by name or subnet (comma-separated)")
	defaultTags       = flag.String("tags", "", "Default tags to apply to all services (comma-separated)")
	deregisterBehavior = flag.String("deregister", "always", "When to deregister containers: 'always' or 'on-success'")
	hostIP            = flag.String("host-ip", "", "Host IP address to use for service registration")
	showVersion       = flag.Bool("version", false, "Show version information")
)

type TraefikRegistrator struct {
	ctx              context.Context
	docker           *client.Client
	consul           *api.Client
	networkPriorities []string
	defaultTags      []string
	syncInterval     time.Duration
	internalMode     bool
	cleanup          bool
	deregisterBehavior string
	hostIP           string
}

// Service represents a container service to be registered in Consul
type Service struct {
	ID          string
	Name        string
	Address     string
	Port        int
	Tags        []string
	CheckTCP    string
	CheckHTTP   string
	CheckHeader map[string][]string
	TraefikHost string
}

func main() {
	// Parse command line flags
	flag.Parse()

	// Apply environment variables as fallbacks for flags
	applyEnvVars()

	if *showVersion {
		fmt.Printf("Traefik Consul Registrator v%s\n", version)
		os.Exit(0)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup Docker client
	docker, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatalf("Failed to create Docker client: %v", err)
	}

	// Test Docker connection
	_, err = docker.Ping(ctx)
	if err != nil {
		log.Fatalf("Failed to connect to Docker: %v", err)
	}

	// Setup Consul client
	consulConfig := api.DefaultConfig()
	consulConfig.Address = *consulAPI

	consul, err := api.NewClient(consulConfig)
	if err != nil {
		log.Fatalf("Failed to create Consul client: %v", err)
	}

	// Test Consul connection
	_, err = consul.Status().Leader()
	if err != nil {
		log.Fatalf("Failed to connect to Consul: %v", err)
	}

	// Use provided host IP or get it from environment
	hostIPToUse := *hostIP
	if hostIPToUse == "" {
		hostIPToUse = os.Getenv("HOST_IP")
		if hostIPToUse == "" {
			// Default to the first non-loopback IPv4 address
			hostIPToUse = getFirstNonLoopbackIP()
			log.Printf("No host IP specified, using detected IP: %s", hostIPToUse)
		} else {
			log.Printf("Using HOST_IP environment variable: %s", hostIPToUse)
		}
	} else {
		log.Printf("Using command-line host IP: %s", hostIPToUse)
	}

	// Split network priorities and default tags
	var networkPriorities []string
	if *networksPriority != "" {
		networkPriorities = strings.Split(*networksPriority, ",")
	}

	var tags []string
	if *defaultTags != "" {
		tags = strings.Split(*defaultTags, ",")
	}

	registrator := &TraefikRegistrator{
		ctx:               ctx,
		docker:            docker,
		consul:            consul,
		networkPriorities: networkPriorities,
		defaultTags:       tags,
		syncInterval:      time.Duration(*syncInterval) * time.Second,
		internalMode:      *internalMode,
		cleanup:           *cleanup,
		deregisterBehavior: *deregisterBehavior,
		hostIP:            hostIPToUse,
	}

	// Handle cleanup if requested
	if registrator.cleanup {
		log.Println("Cleaning up stale services...")
		registrator.cleanupServices()
	}

	// Setup signal handling for graceful shutdown
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		s := <-signals
		log.Printf("Received signal %s, shutting down...", s)
		cancel()
	}()

	// Start event listener
	log.Println("Starting Traefik Consul Registrator...")
	log.Printf("Connecting to Docker and watching for Traefik-labeled containers")
	log.Printf("Consul API endpoint: %s", *consulAPI)
	
	// Perform initial sync
	registrator.syncServices()

	// Start periodic sync if interval > 0
	if registrator.syncInterval > 0 {
		go registrator.periodicSync()
	}

	// Start Docker event listener
	registrator.watchEvents()
}

// applyEnvVars reads environment variables and applies them to flags if not set via command line
func applyEnvVars() {
	// CONSUL_API - Consul API endpoint
	if envVal := os.Getenv("CONSUL_API"); envVal != "" && !isFlagPassed("consul-api") {
		*consulAPI = envVal
		log.Printf("Using environment variable CONSUL_API=%s", envVal)
	}

	// SYNC_INTERVAL - Interval between service synchronizations
	if envVal := os.Getenv("SYNC_INTERVAL"); envVal != "" && !isFlagPassed("sync-interval") {
		if intVal, err := strconv.Atoi(envVal); err == nil {
			*syncInterval = intVal
			log.Printf("Using environment variable SYNC_INTERVAL=%d", intVal)
		}
	}

	// INTERNAL - Use internal container ports
	if envVal := os.Getenv("INTERNAL"); envVal != "" && !isFlagPassed("internal") {
		*internalMode = (envVal == "true" || envVal == "1" || envVal == "yes")
		log.Printf("Using environment variable INTERNAL=%v", *internalMode)
	}

	// CLEANUP - Clean up stale services
	if envVal := os.Getenv("CLEANUP"); envVal != "" && !isFlagPassed("cleanup") {
		*cleanup = (envVal == "true" || envVal == "1" || envVal == "yes")
		log.Printf("Using environment variable CLEANUP=%v", *cleanup)
	}

	// NETWORKS_PRIORITY - Prioritize networks
	if envVal := os.Getenv("NETWORKS_PRIORITY"); envVal != "" && !isFlagPassed("networks-priority") {
		*networksPriority = envVal
		log.Printf("Using environment variable NETWORKS_PRIORITY=%s", envVal)
	}

	// TAGS - Default tags
	if envVal := os.Getenv("TAGS"); envVal != "" && !isFlagPassed("tags") {
		*defaultTags = envVal
		log.Printf("Using environment variable TAGS=%s", envVal)
	}

	// DEREGISTER - Deregister behavior
	if envVal := os.Getenv("DEREGISTER"); envVal != "" && !isFlagPassed("deregister") {
		*deregisterBehavior = envVal
		log.Printf("Using environment variable DEREGISTER=%s", envVal)
	}

	// HOST_IP - Host IP
	if envVal := os.Getenv("HOST_IP"); envVal != "" && !isFlagPassed("host-ip") {
		*hostIP = envVal
		log.Printf("Using environment variable HOST_IP=%s", envVal)
	}
}

// isFlagPassed checks if a flag was explicitly passed on the command line
func isFlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// getFirstNonLoopbackIP returns the first non-loopback IPv4 address
func getFirstNonLoopbackIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Printf("Error getting network interfaces: %v", err)
		return "127.0.0.1"
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}

	return "127.0.0.1"
}

// syncServices synchronizes all running containers with Consul
func (r *TraefikRegistrator) syncServices() {
	log.Println("Synchronizing services...")

	containers, err := r.docker.ContainerList(r.ctx, types.ContainerListOptions{})
	if err != nil {
		log.Printf("Error listing containers: %v", err)
		return
	}

	for _, container := range containers {
		// Skip containers without Traefik labels
		if !r.hasTraefikLabels(container.Labels) {
			continue
		}

		r.registerContainer(container.ID)
	}
}

// periodicSync performs periodic service synchronization
func (r *TraefikRegistrator) periodicSync() {
	ticker := time.NewTicker(r.syncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.syncServices()
		case <-r.ctx.Done():
			return
		}
	}
}

// watchEvents listens for Docker events and reacts to them
func (r *TraefikRegistrator) watchEvents() {
	// Setup filters for container events
	filterArgs := filters.NewArgs()
	filterArgs.Add("type", "container")
	filterArgs.Add("event", "start")
	filterArgs.Add("event", "die")

	eventOptions := types.EventsOptions{
		Filters: filterArgs,
	}

	// Start listening for events
	eventChan, errChan := r.docker.Events(r.ctx, eventOptions)

	for {
		select {
		case event := <-eventChan:
			container := event.Actor.ID

			switch event.Action {
			case "start":
				// Check if container has Traefik labels before registering
				containerInfo, err := r.docker.ContainerInspect(r.ctx, container)
				if err != nil {
					log.Printf("Error inspecting container %s: %v", container, err)
					continue
				}

				if r.hasTraefikLabels(containerInfo.Config.Labels) {
					r.registerContainer(container)
				}
			case "die":
				// Check exit code if deregister behavior is "on-success"
				if r.deregisterBehavior == "on-success" {
					containerInfo, err := r.docker.ContainerInspect(r.ctx, container)
					if err != nil {
						log.Printf("Error inspecting container %s: %v", container, err)
						r.deregisterContainer(container)
						continue
					}

					if containerInfo.State.ExitCode == 0 {
						r.deregisterContainer(container)
					}
				} else {
					// Default behavior is "always"
					r.deregisterContainer(container)
				}
			}
		case err := <-errChan:
			if err != nil {
				log.Printf("Error watching Docker events: %v", err)
				// Try to reconnect
				time.Sleep(5 * time.Second)
				eventChan, errChan = r.docker.Events(r.ctx, eventOptions)
			}
		case <-r.ctx.Done():
			return
		}
	}
}

// registerContainer adds or updates a container in Consul
func (r *TraefikRegistrator) registerContainer(containerID string) {
	container, err := r.docker.ContainerInspect(r.ctx, containerID)
	if err != nil {
		log.Printf("Error inspecting container %s: %v", containerID, err)
		return
	}

	// Skip if container is not running
	if !container.State.Running {
		return
	}

	// Get container info and prepare service details
	containerName := strings.TrimPrefix(container.Name, "/")
	serviceDetails, err := r.buildServiceDetails(container)
	if err != nil {
		log.Printf("Error preparing service details for %s: %v", containerName, err)
		return
	}

	// Register each found service
	for _, service := range serviceDetails {
		r.registerService(service)
	}
}

// buildServiceDetails extracts service information from a container
func (r *TraefikRegistrator) buildServiceDetails(container types.ContainerJSON) ([]Service, error) {
	containerName := strings.TrimPrefix(container.Name, "/")
	
	// Use the host IP for all services
	log.Printf("Using host IP %s for container %s", r.hostIP, containerName)
	
	// Extract Traefik labels
	services := []Service{}
	
	// Process basic service (port-less registration)
	baseName := r.getServiceNameFromLabel(container.Config.Labels, containerName)
	
	// Get Traefik host rule if available
	traefikHost := r.getTraefikHost(container.Config.Labels)
	
	// Find port mappings
	if r.internalMode {
		// Use internal container ports
		for portStr, _ := range container.NetworkSettings.Ports {
			portInfo := strings.Split(string(portStr), "/")
			if len(portInfo) != 2 {
				continue
			}
			
			// Check if this port has Traefik labels
			if !r.isTraefikExposedPort(container.Config.Labels, portInfo[0]) {
				continue
			}
			
			port := portInfo[0]
			portNum := 0
			fmt.Sscanf(port, "%d", &portNum)
			
			if portNum > 0 {
				serviceID := fmt.Sprintf("%s-%s", baseName, port)
				
				service := Service{
					ID:      serviceID,
					Name:    baseName,
					Address: r.hostIP,
					Port:    portNum,
					Tags:    r.buildTags(container.Config.Labels, port),
				}
				
				// Set health check
				if traefikHost != "" {
					service.CheckHTTP = fmt.Sprintf("http://%s:%d/", r.hostIP, portNum)
					service.CheckHeader = map[string][]string{"Host": {traefikHost}}
				} else {
					service.CheckTCP = fmt.Sprintf("%s:%d", r.hostIP, portNum)
				}
				
				services = append(services, service)
			}
		}
	} else {
		// Use published host ports
		for portStr, portBindings := range container.NetworkSettings.Ports {
			if portBindings == nil || len(portBindings) == 0 {
				continue
			}
			
			portInfo := strings.Split(string(portStr), "/")
			if len(portInfo) != 2 {
				continue
			}
			
			// Check if this port has Traefik labels
			if !r.isTraefikExposedPort(container.Config.Labels, portInfo[0]) {
				continue
			}
			
			port := portInfo[0]
			hostPort := portBindings[0].HostPort
			hostPortNum := 0
			fmt.Sscanf(hostPort, "%d", &hostPortNum)
			
			if hostPortNum > 0 {
				serviceID := fmt.Sprintf("%s-%s", baseName, port)
				
				service := Service{
					ID:      serviceID,
					Name:    baseName,
					Address: r.hostIP,
					Port:    hostPortNum,
					Tags:    r.buildTags(container.Config.Labels, port),
				}
				
				// Set health check
				if traefikHost != "" {
					service.CheckHTTP = fmt.Sprintf("http://%s:%d/", r.hostIP, hostPortNum)
					service.CheckHeader = map[string][]string{"Host": {traefikHost}}
				} else {
					service.CheckTCP = fmt.Sprintf("%s:%d", r.hostIP, hostPortNum)
				}
				
				services = append(services, service)
			}
		}
	}
	
	// If no services were created but container has Traefik labels,
	// register a portless service with just the container name
	if len(services) == 0 && r.hasTraefikLabels(container.Config.Labels) {
		service := Service{
			ID:      baseName,
			Name:    baseName,
			Address: r.hostIP,
			Tags:    r.buildTags(container.Config.Labels, ""),
			TraefikHost: traefikHost,
		}
		services = append(services, service)
	}
	
	return services, nil
}

// registerService registers a service with Consul
func (r *TraefikRegistrator) registerService(service Service) {
	log.Printf("Registering service: %s on %s:%d", service.ID, service.Address, service.Port)
	
	// Prepare Consul registration with metadata
	metadata := make(map[string]string)
	
	// Always add basic metadata
	metadata["registered_by"] = "traefik-consul-registrator"
	metadata["registered_at"] = time.Now().Format(time.RFC3339)
	
	// Add domain information as metadata if available
	if service.TraefikHost != "" {
		metadata["domain"] = service.TraefikHost
		log.Printf("Adding domain metadata from TraefikHost: %s for service: %s", service.TraefikHost, service.ID)
	} else {
		// Try to extract domain from tags
		for _, tag := range service.Tags {
			if strings.HasPrefix(tag, "domain:") {
				domain := strings.TrimPrefix(tag, "domain:")
				metadata["domain"] = domain
				log.Printf("Adding domain metadata from tag: %s for service: %s", domain, service.ID)
				break
			}
		}
	}
	
	// Log all metadata being added
	log.Printf("Service metadata for %s:", service.ID)
	for key, value := range metadata {
		log.Printf("  - %s: %s", key, value)
	}
	
	// Create the registration with metadata
	registration := &api.AgentServiceRegistration{
		ID:      service.ID,
		Name:    service.Name,
		Address: service.Address,
		Tags:    service.Tags,
		Meta:    metadata,
	}
	
	if service.Port > 0 {
		registration.Port = service.Port
	}
	
	// Configure health check
	if service.CheckTCP != "" {
		registration.Check = &api.AgentServiceCheck{
			TCP:      service.CheckTCP,
			Interval: "30s",
			Timeout:  "5s",
		}
	} else if service.CheckHTTP != "" {
		registration.Check = &api.AgentServiceCheck{
			HTTP:          service.CheckHTTP,
			Header:        service.CheckHeader,
			Interval:      "30s", 
			Timeout:       "5s",
			Method:        "HEAD",     // Use HEAD instead of GET to minimize response
			TLSSkipVerify: true,       // Skip SSL verification to avoid issues
		}
	} else if service.TraefikHost != "" {
		// Use a TTL check as fallback for services with Traefik host but no direct check
		registration.Check = &api.AgentServiceCheck{
			TTL:    "60s",
			Status: "passing",
		}
	}
	
	// Register with Consul
	err := r.consul.Agent().ServiceRegister(registration)
	if err != nil {
		log.Printf("Error registering service %s: %v", service.ID, err)
	}
}

// deregisterContainer removes a container's services from Consul
func (r *TraefikRegistrator) deregisterContainer(containerID string) {
	container, err := r.docker.ContainerInspect(r.ctx, containerID)
	if err != nil {
		log.Printf("Error inspecting container %s for deregistration: %v", containerID, err)
		return
	}
	
	// Skip if container was not running with Traefik labels
	if !r.hasTraefikLabels(container.Config.Labels) {
		return
	}
	
	containerName := strings.TrimPrefix(container.Name, "/")
	baseName := r.getServiceNameFromLabel(container.Config.Labels, containerName)
	
	// Deregister port-specific services
	for portStr := range container.NetworkSettings.Ports {
		portInfo := strings.Split(string(portStr), "/")
		if len(portInfo) != 2 {
			continue
		}
		
		port := portInfo[0]
		serviceID := fmt.Sprintf("%s-%s", baseName, port)
		
		err := r.consul.Agent().ServiceDeregister(serviceID)
		if err != nil {
			log.Printf("Error deregistering service %s: %v", serviceID, err)
		} else {
			log.Printf("Deregistered service: %s", serviceID)
		}
	}
	
	// Also try to deregister the base service name
	err = r.consul.Agent().ServiceDeregister(baseName)
	if err != nil {
		log.Printf("Error deregistering service %s: %v", baseName, err)
	} else {
		log.Printf("Deregistered service: %s", baseName)
	}
}

// cleanupServices removes stale services from Consul
func (r *TraefikRegistrator) cleanupServices() {
	// Get all services from Consul
	services, err := r.consul.Agent().Services()
	if err != nil {
		log.Printf("Error getting services from Consul: %v", err)
		return
	}
	
	// Build a map of running container service IDs
	runningServices := make(map[string]bool)
	
	containers, err := r.docker.ContainerList(r.ctx, types.ContainerListOptions{})
	if err != nil {
		log.Printf("Error listing containers: %v", err)
		return
	}
	
	for _, container := range containers {
		// Skip containers without Traefik labels
		if !r.hasTraefikLabels(container.Labels) {
			continue
		}
		
		containerName := strings.TrimPrefix(container.Names[0], "/")
		baseName := r.getServiceNameFromLabel(container.Labels, containerName)
		
		// Add all possible service IDs
		runningServices[baseName] = true
		
		// Add port-specific services based on container labels
		// Rather than trying to access port structures that might differ between Docker API versions,
		// we'll look for the known traefik exposure ports in the labels
		for labelName, labelValue := range container.Labels {
			if strings.HasPrefix(labelName, "traefik.http.services.") && strings.Contains(labelName, ".loadbalancer.server.port=") {
				serviceID := fmt.Sprintf("%s-%s", baseName, labelValue)
				runningServices[serviceID] = true
			}
			// Also try published ports from traefik.port label if it exists
			if labelName == "traefik.port" {
				serviceID := fmt.Sprintf("%s-%s", baseName, labelValue)
				runningServices[serviceID] = true
			}
		}
	}
	
	// Deregister services not found in running containers
	for serviceID, service := range services {
		// Only clean up services with our tags
		if r.isOurService(service) && !runningServices[serviceID] {
			err := r.consul.Agent().ServiceDeregister(serviceID)
			if err != nil {
				log.Printf("Error deregistering stale service %s: %v", serviceID, err)
			} else {
				log.Printf("Cleaned up stale service: %s", serviceID)
			}
		}
	}
}

// isInSubnet checks if an IP is in a given subnet
func (r *TraefikRegistrator) isInSubnet(ipStr, subnetStr string) bool {
	if ipStr == "" || subnetStr == "" {
		return false
	}
	
	// Try parsing as CIDR
	_, subnet, err := net.ParseCIDR(subnetStr)
	if err != nil {
		return false
	}
	
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	
	return subnet.Contains(ip)
}

// hasTraefikLabels checks if a container has any Traefik-related labels
func (r *TraefikRegistrator) hasTraefikLabels(labels map[string]string) bool {
	for key := range labels {
		if strings.Contains(strings.ToLower(key), "traefik") {
			return true
		}
	}
	return false
}

// isTraefikExposedPort checks if a specific port is exposed via Traefik
func (r *TraefikRegistrator) isTraefikExposedPort(labels map[string]string, port string) bool {
	// Simple case: Any Traefik label exists
	hasGeneralTraefikLabels := false
	for key := range labels {
		if strings.Contains(strings.ToLower(key), "traefik") {
			hasGeneralTraefikLabels = true
			break
		}
	}
	
	// Look for port-specific Traefik labels
	portSpecificLabel := fmt.Sprintf("traefik.%s.", port)
	for key := range labels {
		if strings.Contains(strings.ToLower(key), strings.ToLower(portSpecificLabel)) {
			return true
		}
	}
	
	// If no port-specific labels but general Traefik labels exist, consider it exposed
	return hasGeneralTraefikLabels
}

// getServiceNameFromLabel extracts the service name from Traefik labels
func (r *TraefikRegistrator) getServiceNameFromLabel(labels map[string]string, defaultName string) string {
	// Check for explicit service name label
	if name, exists := labels["traefik.service.name"]; exists && name != "" {
		return name
	}
	
	// Legacy: Check for SERVICE_NAME
	if name, exists := labels["SERVICE_NAME"]; exists && name != "" {
		return name
	}
	
	// Sanitize container name for use as service name
	return sanitizeName(defaultName)
}

// getTraefikHost extracts the host rule from Traefik labels
func (r *TraefikRegistrator) getTraefikHost(labels map[string]string) string {
	// Debug: Print all Traefik labels to help troubleshoot
	log.Println("Looking for Host rule in Traefik labels:")
	for key, value := range labels {
		if strings.Contains(key, "traefik") {
			log.Printf("  - %s: %s", key, value)
		}
	}
	
	// Traefik v2 - specific common patterns
	for _, pattern := range []string{
		"traefik.http.routers.default.rule",
		"traefik.http.routers.main.rule",
	} {
		if rule, exists := labels[pattern]; exists && strings.Contains(rule, "Host") {
			host := extractHostFromRule(rule)
			log.Printf("Found host from specific pattern %s: %s", pattern, host)
			return host
		}
	}
	
	// Check any router rule pattern - this is the most common
	for key, value := range labels {
		if strings.Contains(key, "traefik.http.routers.") && 
		   strings.Contains(key, ".rule") && 
		   strings.Contains(value, "Host") {
			host := extractHostFromRule(value)
			log.Printf("Found host from router rule %s: %s", key, host)
			return host
		}
	}
	
	// Fallback to any label with traefik, rule, and Host
	for key, value := range labels {
		if strings.Contains(key, "traefik") && 
		   strings.Contains(key, "rule") && 
		   strings.Contains(value, "Host") {
			host := extractHostFromRule(value)
			log.Printf("Found host from generic rule %s: %s", key, host)
			return host
		}
	}
	
	log.Println("No Host rule found in Traefik labels")
	return ""
}

// extractHostFromRule extracts the hostname from a Traefik Host rule
func extractHostFromRule(rule string) string {
    log.Printf("Extracting host from rule: %s", rule)
    
    // Handles the format Host(`domain.com`) with backticks
    re := regexp.MustCompile("Host\\(`([^`]+)`\\)")
    matches := re.FindStringSubmatch(rule)
    if len(matches) > 1 {
        log.Printf("Extracted host: %s", matches[1])
        return matches[1]
    }
    
    // Fallback for other formats
    re = regexp.MustCompile("Host\\([\"']?([^\"'\\)]+)[\"']?\\)")
    matches = re.FindStringSubmatch(rule)
    if len(matches) > 1 {
        log.Printf("Extracted host (alternative format): %s", matches[1])
        return matches[1]
    }
    
    log.Printf("Failed to extract host from rule: %s", rule)
    return ""
}

// buildTags builds a list of tags for a service
func (r *TraefikRegistrator) buildTags(labels map[string]string, port string) []string {
	// Base tag
	tags := []string{"traefik"}
	
	// Add default tags
	tags = append(tags, r.defaultTags...)
	
	// Add port tag if specified
	if port != "" {
		tags = append(tags, fmt.Sprintf("port:%s", port))
	}
	
	// Extract service name
	serviceName := ""
	for key, value := range labels {
		// Look for service name in labels
		if strings.Contains(key, "traefik.http.services.") && strings.Contains(key, ".loadbalancer.server.port") {
			// Extract service name from the label key format: traefik.http.services.[service-name].loadbalancer.server.port
			parts := strings.Split(key, ".")
			if len(parts) > 3 {
				serviceName = parts[3]
				tags = append(tags, fmt.Sprintf("service:%s", serviceName))
			}
		} else if key == "traefik.service" || key == "traefik.service.name" {
			// Direct service name label
			serviceName = value
			tags = append(tags, fmt.Sprintf("service:%s", serviceName))
		}
	}
	
	// Extract domain from Host rule
	domain := r.getTraefikHost(labels)
	if domain != "" {
		tags = append(tags, fmt.Sprintf("domain:%s", domain))
		tags = append(tags, "rule:host")
	}
	
	// Add provider tag (default to docker, as that's what this registrator targets)
	tags = append(tags, "provider:docker")
	
	// Add additional tags from key Traefik labels
	for key, value := range labels {
		// Only process Traefik related labels
		if !strings.Contains(strings.ToLower(key), "traefik") {
			continue
		}
		
		// Skip labels already processed
		if strings.Contains(key, "loadbalancer.server.port") || 
		   key == "traefik.service" || 
		   key == "traefik.service.name" ||
		   (strings.Contains(key, "rule") && strings.Contains(value, "Host")) {
			continue
		}
		
		// Extract entrypoints
		if strings.Contains(key, "entrypoints") || strings.Contains(key, "entryPoints") {
			entrypoints := strings.Split(value, ",")
			for _, ep := range entrypoints {
				ep = strings.TrimSpace(ep)
				if ep != "" {
					tags = append(tags, fmt.Sprintf("entrypoint:%s", ep))
				}
			}
			continue
		}
		
		// Extract middleware information
		if strings.Contains(key, "middlewares") {
			middlewares := strings.Split(value, ",")
			for _, mw := range middlewares {
				mw = strings.TrimSpace(mw)
				if mw != "" {
					tags = append(tags, fmt.Sprintf("middleware:%s", mw))
				}
			}
			continue
		}
		
		// Handle boolean flags
		if value == "true" || value == "false" {
			if value == "true" {
				// Extract simplified key for the tag
				tagKey := extractTagKey(key)
				tags = append(tags, tagKey)
			}
			continue
		}
		
		// Handle standard key-value pairs (with reasonable lengths)
		if len(value) < 50 {
			tagKey := extractTagKey(key)
			tags = append(tags, fmt.Sprintf("%s:%s", tagKey, value))
		}
	}
	
	// Check for auto-update related labels (watchtower, etc.)
	for key, value := range labels {
		if strings.Contains(key, "watchtower") && value == "true" {
			tags = append(tags, "auto-update")
			tags = append(tags, "managed-by:watchtower")
		}
	}
	
	// Remove duplicate tags
	return uniqueTags(tags)
}

// extractTagKey converts a Traefik label key to a simplified tag key
func extractTagKey(key string) string {
	// Remove traefik. prefix
	tagKey := strings.Replace(key, "traefik.", "", 1)
	
	// Further simplify nested paths
	if strings.Contains(tagKey, "http.routers.") {
		tagKey = strings.Replace(tagKey, "http.routers.", "router:", 1)
	} else if strings.Contains(tagKey, "http.services.") {
		tagKey = strings.Replace(tagKey, "http.services.", "service:", 1)
	} else if strings.Contains(tagKey, "http.middlewares.") {
		tagKey = strings.Replace(tagKey, "http.middlewares.", "middleware:", 1)
	}
	
	// Replace dots with underscores for better tag readability
	tagKey = strings.Replace(tagKey, ".", "_", -1)
	
	// Limit tag key length
	if len(tagKey) > 30 {
		tagKey = tagKey[:30]
	}
	
	return tagKey
}

// uniqueTags removes duplicate tags
func uniqueTags(tags []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	
	for _, tag := range tags {
		if !seen[tag] {
			seen[tag] = true
			result = append(result, tag)
		}
	}
	
	return result
}

// isOurService checks if a service was registered by this registrator
func (r *TraefikRegistrator) isOurService(service *api.AgentService) bool {
	for _, tag := range service.Tags {
		if tag == "traefik" {
			return true
		}
	}
	return false
}

// sanitizeName converts a string to a valid service name
func sanitizeName(name string) string {
	return regexp.MustCompile(`[^a-zA-Z0-9_-]`).ReplaceAllString(name, "-")
}