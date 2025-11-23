package plugin

import (
	"fmt"
)

// Loader handles loading and managing plugins
type Loader struct {
	plugins []Plugin
}

// NewLoader creates a new plugin loader
func NewLoader(plugins []Plugin) (*Loader, error) {
	loader := &Loader{}
	if err := loader.Load(plugins); err != nil {
		return nil, err
	}
	return loader, nil
}

// Load loads plugins from the hardcoded registry
func (l *Loader) Load(plugins []Plugin) error {

	l.plugins = plugins
	fmt.Printf("Loaded %d plugin(s) from hardcoded registry\n", len(l.plugins))
	return nil
}

// GetPlugins returns all loaded plugins
func (l *Loader) GetPlugins() []Plugin {
	return l.plugins
}

// MatchPlugin finds the first plugin that matches the given hostname
func (l *Loader) MatchPlugin(hostname string) *Plugin {
	for i := range l.plugins {
		if isMatch(hostname, l.plugins[i].Match) {
			return &l.plugins[i]
		}
	}
	return nil
}
