package limits

const IncludedWindowBytesPerToken = 4

const KiB = 1024

type Kibibytes int

func KibibytesCovering(bytes int) Kibibytes { return Kibibytes((bytes + KiB - 1) / KiB) }

func (k Kibibytes) Bytes() int { return int(k) * KiB }

const (
	CharacterMessageTokens = 2_000
	CharacterMessageBytes  = CharacterMessageTokens * IncludedWindowBytesPerToken
)

const IncludedEncryptedAllowanceBytes = 1 << 20

const IncludedOutputTokens = 32_768

const MaxRateLimitRPM = 1_000_000

func ValidRateLimitRPM(rpm int) bool { return rpm >= 1 && rpm <= MaxRateLimitRPM }

type SharedLimit struct {
	Subject string
	RPM     int
}

func (l SharedLimit) Valid() bool { return l.Subject != "" && ValidRateLimitRPM(l.RPM) }
