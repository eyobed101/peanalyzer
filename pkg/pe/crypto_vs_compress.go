package pe

type CompressionVsEncryption struct {
	SectionName		string	`json:"section_name"`
	Entropy			float64	`json:"entropy"`
	LikelyCompressed	bool	`json:"likely_compressed"`
	LikelyEncrypted		bool	`json:"likely_encrypted"`
	Confidence		string	`json:"confidence"`
}

func AnalyzeCompressionVsEncryption(data []byte) *CompressionVsEncryption {
	if len(data) == 0 {
		return nil
	}
	entropy := CalculateEntropy(data)

	freq := make([]int, 256)
	for _, b := range data {
		freq[b]++
	}

	avg := len(data) / 256
	lowCount := 0
	for _, f := range freq {
		if f < avg/10 {
			lowCount++
		}
	}

	res := &CompressionVsEncryption{
		Entropy:		entropy,
		LikelyCompressed:	false,
		LikelyEncrypted:	false,
		Confidence:		"low",
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

			res.Confidence = "low"
		}
	}
	return res
}
