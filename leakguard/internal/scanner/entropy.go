package scanner

import "math"

// ShannonEntropy returns the entropy (bits per char) of s.
func ShannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]float64{}
	n := 0.0
	for _, c := range s {
		freq[c]++
		n++
	}
	var e float64
	for _, f := range freq {
		p := f / n
		e -= p * math.Log2(p)
	}
	return e
}
