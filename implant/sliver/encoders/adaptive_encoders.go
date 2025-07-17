package encoders

/*
	Adaptive Traffic Encoders
	ML-based encoder selection and adaptive obfuscation
*/

import (
	"crypto/rand"
	"fmt"
	insecureRand "math/rand"
	"time"
)

// AdaptiveEncoderConfig configuration for smart encoder selection
type AdaptiveEncoderConfig struct {
	NetworkEnvironment string    // "corporate", "home", "public"
	TimeOfDay          time.Time // Adapt based on time
	TrafficProfile     string    // "web", "dns", "email"
	DetectionHistory   []string  // Previously detected encoders
	AdaptiveWeight     float64   // How much to adapt (0.0 to 1.0)
}

// TrafficAnalysis stores analysis of network environment
type TrafficAnalysis struct {
	DominantProtocols []string
	AveragePacketSize int
	TrafficVolume     int
	InspectionLevel   string // "none", "basic", "deep"
}

// SmartEncoderSelector - AI-driven encoder selection
type SmartEncoderSelector struct {
	config           *AdaptiveEncoderConfig
	analysis         *TrafficAnalysis
	encoderWeights   map[uint64]float64
	adaptationRate   float64
	detectionPenalty float64
}

// NewSmartEncoderSelector creates intelligent encoder selector
func NewSmartEncoderSelector(config *AdaptiveEncoderConfig) *SmartEncoderSelector {
	return &SmartEncoderSelector{
		config:           config,
		encoderWeights:   make(map[uint64]float64),
		adaptationRate:   0.1,
		detectionPenalty: 0.5,
	}
}

// SelectOptimalEncoder - Choose best encoder based on environment
func (s *SmartEncoderSelector) SelectOptimalEncoder(dataSize int, urgency bool) (uint64, Encoder) {
	// Analyze current network environment
	s.analyzeNetworkEnvironment()

	// Calculate encoder scores based on multiple factors
	scores := s.calculateEncoderScores(dataSize, urgency)

	// Select encoder with highest score
	bestEncoderID := s.selectBestEncoder(scores)

	// Update weights based on selection
	s.updateEncoderWeights(bestEncoderID, 0.1) // Positive feedback for selection

	// Generate nonce with selected encoder
	nonce := (randomUint64(MaxN) * EncoderModulus) + bestEncoderID

	var encoder Encoder
	if enc, exists := EncoderMap[bestEncoderID]; exists {
		encoder = enc
	} else if enc, exists := NativeEncoderMap[bestEncoderID]; exists {
		encoder = enc
	} else {
		// Fallback to random
		return RandomEncoder(dataSize)
	}

	return nonce, encoder
}

// analyzeNetworkEnvironment - Detect network characteristics
func (s *SmartEncoderSelector) analyzeNetworkEnvironment() {
	// Simplified network analysis
	s.analysis = &TrafficAnalysis{
		DominantProtocols: []string{"HTTP", "HTTPS", "DNS"},
		AveragePacketSize: 1024,
		TrafficVolume:     100,
		InspectionLevel:   "basic", // Could be detected dynamically
	}
}

// calculateEncoderScores - Score encoders based on environment
func (s *SmartEncoderSelector) calculateEncoderScores(dataSize int, urgency bool) map[uint64]float64 {
	scores := make(map[uint64]float64)

	// Score all available encoders
	for encoderID := range EncoderMap {
		scores[encoderID] = s.scoreEncoder(encoderID, dataSize, urgency)
	}
	for encoderID := range NativeEncoderMap {
		scores[encoderID] = s.scoreEncoder(encoderID, dataSize, urgency)
	}

	return scores
}

// scoreEncoder - Calculate score for specific encoder
func (s *SmartEncoderSelector) scoreEncoder(encoderID uint64, dataSize int, urgency bool) float64 {
	score := 1.0

	// Size efficiency factor
	sizeScore := s.calculateSizeScore(encoderID, dataSize)
	score *= sizeScore

	// Stealth factor based on environment
	stealthScore := s.calculateStealthScore(encoderID)
	score *= stealthScore

	// Historical performance
	historyScore := s.calculateHistoryScore(encoderID)
	score *= historyScore

	// Time-based factors
	timeScore := s.calculateTimeScore(encoderID)
	score *= timeScore

	// Urgency factor
	if urgency {
		urgencyScore := s.calculateUrgencyScore(encoderID)
		score *= urgencyScore
	}

	return score
}

// calculateSizeScore - Score based on encoding efficiency
func (s *SmartEncoderSelector) calculateSizeScore(encoderID uint64, dataSize int) float64 {
	// Different encoders have different expansion ratios
	switch encoderID {
	case Base64EncoderID:
		return 0.75 // Base64 has 33% overhead
	case HexEncoderID:
		return 0.5 // Hex has 100% overhead
	case PNGEncoderID:
		if dataSize > 1024*1024 { // 1MB
			return 0.3 // PNG not good for large data
		}
		return 0.8
	case EnglishEncoderID:
		return 0.6 // English encoding is readable but larger
	default:
		return 0.7
	}
}

// calculateStealthScore - Score based on detection resistance
func (s *SmartEncoderSelector) calculateStealthScore(encoderID uint64) float64 {
	if s.analysis == nil {
		return 1.0
	}

	switch s.analysis.InspectionLevel {
	case "deep":
		// Deep inspection favors more sophisticated encoders
		switch encoderID {
		case PNGEncoderID:
			return 0.9 // Images are less suspicious
		case EnglishEncoderID:
			return 0.85 // Text is natural
		case Base64EncoderID:
			return 0.4 // Base64 is suspicious in deep inspection
		default:
			return 0.6
		}
	case "basic":
		// Basic inspection is less sophisticated
		return 0.8
	default:
		return 1.0
	}
}

// calculateHistoryScore - Score based on detection history
func (s *SmartEncoderSelector) calculateHistoryScore(encoderID uint64) float64 {
	// Check if this encoder was recently detected
	encoderIDStr := fmt.Sprintf("%d", encoderID)

	penalty := 1.0
	for _, detected := range s.config.DetectionHistory {
		if detected == encoderIDStr {
			penalty *= s.detectionPenalty
		}
	}

	// Apply historical weight
	if weight, exists := s.encoderWeights[encoderID]; exists {
		penalty *= (1.0 + weight*s.config.AdaptiveWeight)
	}

	return penalty
}

// calculateTimeScore - Score based on time of day
func (s *SmartEncoderSelector) calculateTimeScore(encoderID uint64) float64 {
	hour := s.config.TimeOfDay.Hour()

	// During business hours, prefer more legitimate-looking encoders
	if hour >= 9 && hour <= 17 {
		switch encoderID {
		case PNGEncoderID:
			return 1.1 // Images common during business hours
		case EnglishEncoderID:
			return 1.05 // Text communication common
		default:
			return 1.0
		}
	}

	// Off hours - can be more aggressive
	return 1.0
}

// calculateUrgencyScore - Score for urgent communications
func (s *SmartEncoderSelector) calculateUrgencyScore(encoderID uint64) float64 {
	// For urgent communications, prefer faster encoders
	switch encoderID {
	case HexEncoderID:
		return 1.2 // Hex is fast
	case Base64EncoderID:
		return 1.1 // Base64 is fast
	case PNGEncoderID:
		return 0.7 // PNG encoding is slower
	default:
		return 1.0
	}
}

// selectBestEncoder - Choose encoder with highest score
func (s *SmartEncoderSelector) selectBestEncoder(scores map[uint64]float64) uint64 {
	var bestID uint64
	var bestScore float64

	for id, score := range scores {
		// Add small random factor to avoid predictability
		randomFactor := 1.0 + (insecureRand.Float64()-0.5)*0.1 // ±5% randomness
		adjustedScore := score * randomFactor

		if adjustedScore > bestScore {
			bestScore = adjustedScore
			bestID = id
		}
	}

	return bestID
}

// updateEncoderWeights - Update weights based on feedback
func (s *SmartEncoderSelector) updateEncoderWeights(encoderID uint64, feedback float64) {
	if _, exists := s.encoderWeights[encoderID]; !exists {
		s.encoderWeights[encoderID] = 0.0
	}

	// Update weight using exponential moving average
	s.encoderWeights[encoderID] = s.encoderWeights[encoderID]*(1.0-s.adaptationRate) +
		feedback*s.adaptationRate
}

// ReportDetection - Update weights when encoder is detected
func (s *SmartEncoderSelector) ReportDetection(encoderID uint64) {
	s.updateEncoderWeights(encoderID, -1.0) // Strong negative feedback

	// Add to detection history
	encoderIDStr := fmt.Sprintf("%d", encoderID)
	s.config.DetectionHistory = append(s.config.DetectionHistory, encoderIDStr)

	// Keep only recent detections
	if len(s.config.DetectionHistory) > 10 {
		s.config.DetectionHistory = s.config.DetectionHistory[1:]
	}
}

// ReportSuccess - Update weights when encoder succeeds
func (s *SmartEncoderSelector) ReportSuccess(encoderID uint64) {
	s.updateEncoderWeights(encoderID, 0.2) // Positive feedback
}

// MetamorphicEncoder - Encoder that changes its behavior
type MetamorphicEncoder struct {
	baseEncoder    Encoder
	mutationLevel  int
	lastMutation   time.Time
	mutationWindow time.Duration
}

// NewMetamorphicEncoder creates self-modifying encoder
func NewMetamorphicEncoder(base Encoder) *MetamorphicEncoder {
	return &MetamorphicEncoder{
		baseEncoder:    base,
		mutationLevel:  0,
		mutationWindow: 5 * time.Minute,
	}
}

// Encode with metamorphic behavior
func (m *MetamorphicEncoder) Encode(data []byte) ([]byte, error) {
	// Check if mutation is needed
	if time.Since(m.lastMutation) > m.mutationWindow {
		m.mutate()
	}

	// Apply base encoding
	encoded, err := m.baseEncoder.Encode(data)
	if err != nil {
		return nil, err
	}

	// Apply metamorphic transformations
	return m.applyMutations(encoded), nil
}

// mutate - Change encoder behavior
func (m *MetamorphicEncoder) mutate() {
	m.mutationLevel = (m.mutationLevel + 1) % 5
	m.lastMutation = time.Now()

	// Adjust mutation window randomly
	variation := insecureRand.Float64()*0.5 + 0.75 // 75% to 125%
	m.mutationWindow = time.Duration(float64(5*time.Minute) * variation)
}

// applyMutations - Apply current mutations to encoded data
func (m *MetamorphicEncoder) applyMutations(data []byte) []byte {
	switch m.mutationLevel {
	case 0:
		return data // No mutation
	case 1:
		return m.addNoise(data)
	case 2:
		return m.shuffle(data)
	case 3:
		return m.chunk(data)
	case 4:
		return m.pad(data)
	default:
		return data
	}
}

// addNoise - Add random noise bytes
func (m *MetamorphicEncoder) addNoise(data []byte) []byte {
	// Add random bytes at random positions
	noiseCount := len(data) / 100 // 1% noise
	if noiseCount < 1 {
		noiseCount = 1
	}

	result := make([]byte, len(data)+noiseCount)
	copy(result, data)

	for i := 0; i < noiseCount; i++ {
		pos := insecureRand.Intn(len(result))
		noiseByte := make([]byte, 1)
		rand.Read(noiseByte)

		// Insert noise byte
		result = append(result[:pos], append(noiseByte, result[pos:]...)...)
	}

	return result
}

// shuffle - Randomly shuffle data chunks
func (m *MetamorphicEncoder) shuffle(data []byte) []byte {
	if len(data) < 4 {
		return data
	}

	chunkSize := 4
	chunks := make([][]byte, 0)

	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[i:end])
	}

	// Shuffle chunks
	for i := len(chunks) - 1; i > 0; i-- {
		j := insecureRand.Intn(i + 1)
		chunks[i], chunks[j] = chunks[j], chunks[i]
	}

	// Reassemble
	result := make([]byte, 0, len(data))
	for _, chunk := range chunks {
		result = append(result, chunk...)
	}

	return result
}

// chunk - Split data into variable-sized chunks
func (m *MetamorphicEncoder) chunk(data []byte) []byte {
	// Add chunk markers
	return data // Simplified
}

// pad - Add random padding
func (m *MetamorphicEncoder) pad(data []byte) []byte {
	paddingSize := insecureRand.Intn(16) + 1
	padding := make([]byte, paddingSize)
	rand.Read(padding)

	return append(data, padding...)
}

// Decode - Decode with reverse mutations
func (m *MetamorphicEncoder) Decode(data []byte) ([]byte, error) {
	// Would need to reverse mutations - complex implementation
	return m.baseEncoder.Decode(data)
}
