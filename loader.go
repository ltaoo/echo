package echo

import (
	"net"
	"net/http"
	"strings"
)

// PluginLoader handles loading and managing plugins
type PluginLoader struct {
	plugins []*Plugin
}

// NewPluginLoader creates a new plugin loader
func NewPluginLoader(plugins []*Plugin) (*PluginLoader, error) {
	loader := &PluginLoader{}
	if err := loader.Load(plugins); err != nil {
		return nil, err
	}
	return loader, nil
}

// Load loads plugins from the hardcoded registry
func (l *PluginLoader) Load(plugins []*Plugin) error {

	l.plugins = plugins
	// fmt.Printf("Loaded %d plugin(s) from hardcoded registry\n", len(l.plugins))
	return nil
}

func (l *PluginLoader) AddPlugin(plugin *Plugin) {
	l.plugins = append(l.plugins, plugin)
}

// GetPlugins returns all loaded plugins
func (l *PluginLoader) GetPlugins() []*Plugin {
	return l.plugins
}

// MatchPlugin finds the first plugin that matches the given hostname
func (l *PluginLoader) MatchPlugin(hostname string) *Plugin {
	for i := range l.plugins {
		if IsMatch(hostname, l.plugins[i].Match) {
			return l.plugins[i]
		}
	}
	return nil
}

// MatchPlugins returns all plugins that match the given hostname, in order
func (l *PluginLoader) MatchPlugins(hostname string) []*Plugin {
	var matches []*Plugin
	for i := range l.plugins {
		if IsMatch(hostname, l.plugins[i].Match) {
			matches = append(matches, l.plugins[i])
		}
	}
	return matches
}

func (l *PluginLoader) MatchPluginForRequest(r *http.Request) *Plugin {
	if r == nil {
		return nil
	}
	scheme := r.URL.Scheme
	if scheme == "" {
		scheme = "http"
	}
	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	fullURL := scheme + "://" + host + r.URL.Path
	if r.URL.RawQuery != "" {
		fullURL += "?" + r.URL.RawQuery
	}

	hostname := r.URL.Hostname()
	if hostname == "" {
		hostname = r.Host
		if h, _, err := net.SplitHostPort(hostname); err == nil {
			hostname = h
		}
	}

	for i := range l.plugins {
		pattern := l.plugins[i].Match
		if containsScheme(pattern) || strings.Contains(pattern, "/") {
			if IsMatch(fullURL, pattern) {
				return l.plugins[i]
			}
		} else if IsMatch(hostname, pattern) {
			return l.plugins[i]
		}
	}
	return nil
}

// MatchPluginsForRequest returns all plugins that match the given request URL/host, in order
func (l *PluginLoader) MatchPluginsForRequest(r *http.Request) []*Plugin {
	if r == nil {
		return nil
	}
	scheme := r.URL.Scheme
	if scheme == "" {
		scheme = "http"
	}
	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	fullURL := scheme + "://" + host + r.URL.Path
	if r.URL.RawQuery != "" {
		fullURL += "?" + r.URL.RawQuery
	}

	hostname := r.URL.Hostname()
	if hostname == "" {
		hostname = r.Host
		if h, _, err := net.SplitHostPort(hostname); err == nil {
			hostname = h
		}
	}

	var matches []*Plugin
	for i := range l.plugins {
		pattern := l.plugins[i].Match
		if containsScheme(pattern) || strings.Contains(pattern, "/") {
			if IsMatch(fullURL, pattern) {
				matches = append(matches, l.plugins[i])
			}
		} else if IsMatch(hostname, pattern) {
			matches = append(matches, l.plugins[i])
		}
	}
	return matches
}
func containsScheme(s string) bool {
	return strings.HasPrefix(s, "http://") ||
		strings.HasPrefix(s, "https://") ||
		strings.HasPrefix(s, "ws://") ||
		strings.HasPrefix(s, "wss://")
}
