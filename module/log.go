package module

import "go.uber.org/zap"

// zapField wraps zap.Any so callers don't have to import zap directly.
func zapField(key string, value interface{}) zap.Field {
	return zap.Any(key, value)
}
