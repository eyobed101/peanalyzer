package peanalyzer

// CompressionVsEncryption holds results of compression vs encryption analysis for a section.
type CompressionVsEncryption struct {
	SectionName      string  `json:"section_name"`
	Entropy          float64 `json:"entropy"`
	LikelyCompressed bool    `json:"likely_compressed"`
	LikelyEncrypted  bool    `json:"likely_encrypted"`
	Confidence       string  `json:"confidence"` // "low", "medium", "high"
}

// AnalyzeCompressionVsEncryption uses byte frequency distribution to guess if data is compressed or encrypted.
func AnalyzeCompressionVsEncryption(data []byte) *CompressionVsEncryption {
	if len(data) == 0 {
		return nil
	}
	entropy := CalculateEntropy(data)
	// Frequency of each byte
	freq := make([]int, 256)
	for _, b := range data {
		freq[b]++
	}
	// Count how many byte values appear less than average (10% of occurrences)
	avg := len(data) / 256
	lowCount := 0
	for _, f := range freq {
		if f < avg/10 {
			lowCount++
		}
	}
	// Compressed data often has many low‑frequency bytes but not perfectly uniform.
	// Encrypted data tends to have a more even distribution (lowCount closer to 0).
	// Heuristic: if lowCount > 200 and entropy > 7.0 => likely compressed
	// if lowCount < 50 and entropy > 7.5 => likely encrypted
	res := &CompressionVsEncryption{
		Entropy:          entropy,
		LikelyCompressed: false,
		LikelyEncrypted:  false,
		Confidence:       "low",
	}
	if entropy > 7.0 {
		if lowCount > 200 {
			res.LikelyCompressed = true
			res.Confidence = "medium"
		} else if lowCount < 50 {
			if entropy > 7.5 {
				res.LikelyEncrypted = true
				res.Confidence = "high"
			}
		} else {
			// Inconclusive
			res.Confidence = "low"
		}
	}
	return res
}
